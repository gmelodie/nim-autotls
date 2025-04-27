# run with:
# nim c -d:ssl -r acme.nim

import std/[base64, options, os, strformat, osproc, random, strutils, json, net]
import chronos, bio, jwt, jsony, nimcrypto, libp2p, stew/base36
import libp2p/transports/tls/certificate_ffi
import libp2p/transports/tls/certificate
import std/sysrand
import chronos/apps/http/httpclient

const
  LetsEncryptURL = "https://acme-staging-v02.api.letsencrypt.org"
  AutoTLSBroker = "https://registration.libp2p.direct"
  AutoTLSDNSServer = "libp2p.direct"
  Alg = "RS256"

type Account = ref object
  status*: string
  contact*: seq[string]
  privKey: string
  kid*: string

type SigParam = object
  k: string
  v: seq[byte]

type RSAPrivateKey = object
  n, e, d, p, q, dmp1, dmq1, iqmp: seq[byte]

proc base64UrlEncode(data: seq[byte]): string =
  ## Encodes data using base64url (RFC 4648 §5) — no padding, URL-safe
  result = base64.encode(data, safe = true)
  result.removeSuffix("=")
  result.removeSuffix("=")

proc base64UrlEncodeNoSuffix(data: seq[byte]): string =
  ## Encodes data using base64url (RFC 4648 §5) — no padding, URL-safe
  result = base64.encode(data, safe = true)

proc genTempFilename(prefix: string, suffix: string): string =
  ## Generates a unique temporary file name with the given prefix and suffix.
  let tempDir = getTempDir()
  let randomPart = rand(1_000_000).intToStr()
  result = fmt"{tempDir}/{prefix}{randomPart}{suffix}"

proc loadRsaKey*(pemData: string): RSAPrivateKey =
  ## Loads an RSA private key from PEM-encoded string data.
  ##
  ## Parameters:
  ##   - pemData: The PEM-encoded RSA private key.
  ##
  ## Returns:
  ##   - An RSAPrivateKey object representing the loaded key.
  let pemFile = genTempFilename("acme_key_", ".pem")
  writeFile(pemFile, pemData)

  var n, e, d, p, q, dmp1, dmq1, iqmp: seq[byte]
  let modCmd = "openssl rsa -in " & pemFile & " -noout -modulus"
  let (modOutput, modExitCode) = execCmdEx(modCmd)
  if modExitCode == 0 and modOutput.startsWith("Modulus="):
    let modHex = modOutput.splitLines()[0][8 ..^ 1]
    n = newSeq[byte](modHex.len div 2)
    for i in countup(0, modHex.len - 2, 2):
      n[i div 2] = byte(parseHexInt(modHex[i .. i + 1]))

  let textCmd = "openssl rsa -in " & pemFile & " -noout -text"
  let (textOutput, textExitCode) = execCmdEx(textCmd)

  if textExitCode != 0:
    removeFile(pemFile)
    raise newException(IOError, "Failed to load RSA private key: " & textOutput)

  for line in textOutput.splitLines():
    if line.contains("publicExponent:"):
      let parts = line.split("(")
      if parts.len > 1:
        let exponentStr = parts[1].split(")")[0]
        let expValue = parseHexInt(exponentStr.replace("0x", ""))
        e = @[(expValue shr 16).byte, (expValue shr 8).byte, expValue.byte]
      break

  removeFile(pemFile)

  result =
    RSAPrivateKey(n: n, e: e, d: d, p: p, q: q, dmp1: dmp1, dmq1: dmq1, iqmp: iqmp)

proc generateRsaKey*(bits = 2048): string =
  ## Generates a new RSA private key with the specified bit size.
  ##
  ## Parameters:
  ##   - bits: The RSA key size in bits. Default is 2048.
  ##
  ## Returns:
  ##   - The generated RSA private key in PEM format.
  ##
  ## Example:
  ##   ```nim
  ##   let privateKey = generateRsaKey(4096) # Generate a 4096-bit RSA key
  ##   writeFile("domain.key", privateKey)
  ##   ```
  let tmpFile = genTempFilename("acme_key_", ".pem")
  let cmd = "openssl genrsa -out " & tmpFile & " " & $bits
  let (output, exitCode) = execCmdEx(cmd)

  if exitCode != 0:
    raise newException(IOError, "Failed to generate RSA key: " & output)

  result = readFile(tmpFile)
  writeFile("/tmp/domain.key", result)
  removeFile(tmpFile)

proc getDirectory(): Future[JsonNode] {.async.} =
  let resp = await HttpClientRequestRef.get(HttpSessionRef.new(), LetsEncryptURL & "/directory").get().send()
  let resp_body = bytesToString(await resp.getBodyBytes())
  let directory = resp_body.parseJson()
  return directory

proc getNewNonce(): Future[string] {.async.} =
  let directory = await getDirectory()
  let nonceURL = directory["newNonce"].getStr
  let resp = await HttpClientRequestRef.get(HttpSessionRef.new(), nonceURL).get().send()
  return resp.headers.getString("replay-nonce")

proc getAcmeHeader(
    acc: Account,
    url: string,
    needsJwk: bool,
    n: string = "",
    e: string = "",
    kid: string = "",
): Future[JsonNode] {.async.} =
  let key = loadRsaKey(acc.privKey)
  let n = base64UrlEncode(key.n)
  let e = base64UrlEncode(key.e)
  let newNonce = await getNewNonce()
  var header = %*{"alg": Alg, "typ": "JWT", "nonce": newNonce, "url": url}
  if needsJwk:
    header["jwk"] = %*{"kty": "RSA", "n": n, "e": e}
  else:
    header["kid"] = %*(acc.kid)
  return header

proc makeSignedAcmeRequest(
    acc: Account, url: string, payload: JsonNode, needsJwk: bool = false
): Future[HttpClientResponseRef] {.async.} =
  let acmeHeader = await acc.getAcmeHeader(url, needsJwk)
  var token = toJWT(%*{"header": acmeHeader, "claims": payload})
  token.sign(acc.privKey)

  let body =
    %*{
      "payload": token.claims.toBase64,
      "protected": token.header.toBase64,
      "signature": base64UrlEncode(token.signature),
    }

  return await HttpClientRequestRef.post(HttpSessionRef.new(), url, body = $body, headers = [("Content-Type", "application/jose+json")]).get().send()


proc registerAccount(acc: Account) {.async raises: [Exception].} =
  let registerAccountPayload = %*{"termsOfServiceAgreed": true}
  let directory = await getDirectory()
  let resp = await acc.makeSignedAcmeRequest(
    directory["newAccount"].getStr, registerAccountPayload, needsJwk = true
  )
  var account = bytesToString(await resp.getBodyBytes()).fromJson(Account)
  acc.kid = resp.headers.getString("location")
  acc.status = account.status
  acc.contact = account.contact

proc requestChallenge(acc: Account, domains: seq[string]): Future[(JsonNode, string)] {.async.} =
  var orderPayload = %*{"identifiers": []}
  for domain in domains:
    orderPayload["identifiers"].add(%*{"type": "dns", "value": domain})
  let directory = await getDirectory()
  let resp = await acc.makeSignedAcmeRequest(directory["newOrder"].getStr, orderPayload)

  let respBody = bytesToString(await resp.getBodyBytes()).parseJson()
  echo respBody
  let finalizeURL = respBody["finalize"].getStr

  # get challenges
  let authz_url = respBody["authorizations"][0].getStr
  let auth_resp = await HttpClientRequestRef.get(HttpSessionRef.new(), authz_url).get().send()
  let authz = bytesToString(await auth_resp.getBodyBytes()).parseJson()

  let challenges = authz["challenges"]

  var dns01: JsonNode = nil
  for item in challenges:
    if item["type"].getStr() == "dns-01":
      dns01 = item
      break

  # TODO: error dns01 not found
  return (dns01, finalizeURL)

proc newAccount(): Account =
  var account: Account
  new(account)
  account.privKey = generateRsaKey()
  return account

proc thumbprint(key: RSAPrivateKey): string =
  let n = base64UrlEncode(key.n)
  let e = base64UrlEncode(key.e)
  let keyJson = %*{"e": e, "kty": "RSA", "n": n}
  # TODO: https://www.rfc-editor.org/rfc/rfc7638
  let digest = sha256.digest($keyJson)
  return base64UrlEncode(@(digest.data))

proc encodeVarint(n: int): seq[byte] =
  result = @[]
  var x = uint64(n)
  while true:
    var byteVal = byte(x and 0x7F)
    x = x shr 7
    if x != 0:
      byteVal = byteVal or 0x80
    result.add byteVal
    if x == 0:
      break

# Helper to extract quoted value from key
proc extractField(data, key: string): string =
  for segment in data.split(","):
    if key in segment:
      return segment.split("=", 1)[1].strip(chars = {' ', '"'})
  return ""

proc randomChallenge(): string =
  randomize()
  let charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
  result = ""
  for _ in 0 ..< 48:
    result.add sample(charset)

proc genDataToSign(prefix: string, parts: seq[SigParam]): seq[byte] =
  var buf: seq[byte] = prefix.toByteSeq()
  for p in parts:
    buf.add encodeVarint(p.k.len + p.v.len + 1)
    buf.add (p.k & "=").toByteSeq
    buf.add p.v
  return buf

proc peerIdSign(
    privateKey: PrivateKey,
    challenge: string,
    publicKey: PublicKey,
    hostname: string,
    clientSender: bool = true,
): string =
  let prefix = "libp2p-PeerID"
  let parts =
    # parts need to be sorted alphabetically by key
    if clientSender:
      @[
        SigParam(k: "challenge-client", v: challenge.toByteSeq()),
        SigParam(k: "hostname", v: hostname.toByteSeq()),
        SigParam(k: "server-public-key", v: publicKey.getBytes().get()),
      ]
    else:
      @[
        SigParam(k: "challenge-server", v: challenge.toByteSeq()),
        SigParam(k: "client-public-key", v: publicKey.getBytes().get()),
        SigParam(k: "hostname", v: hostname.toByteSeq),
      ]
  let bytesToSign = genDataToSign(prefix, parts)
  result = base64UrlEncodeNoSuffix(privateKey.sign(bytesToSign).get().getBytes())

proc peerIDAuth(
    peerID: string, privateKey: PrivateKey, pubKey: PublicKey, payload: JsonNode
): Future[string] {.async.} =
  let registrationURL = fmt"{AutoTLSBroker}/v1/_acme-challenge"

  let resp1 = await HttpClientRequestRef.get(HttpSessionRef.new(), registrationURL).get().send()

  let wwwAuthenticate = resp1.headers.getString("www-authenticate")

  let challengeClient = extractField(wwwAuthenticate, "challenge-client")
  let serverPublicKey =
    PublicKey.init(decode(extractField(wwwAuthenticate, "public-key")).toByteSeq).get()
  let opaque = extractField(wwwAuthenticate, "opaque")
  let hostname = "registration.libp2p.direct"

  echo "2.WWW-AUTHENTICATE"
  echo "challenge-client: ", challengeClient
  echo "server-public-key: ", $serverPublicKey
  echo "opaque: ", opaque
  let clientPubKeyB64 = base64UrlEncodeNoSuffix(pubKey.getBytes().get())
  let challengeServer = randomChallenge()
  let sig = peerIdSign(privateKey, challengeClient, serverPublicKey, hostname)

  let authHeader =
    "libp2p-PeerID public-key=\"" & clientPubKeyB64 & "\"" & ", opaque=\"" & opaque &
    "\"" & ", challenge-server=\"" & challengeServer & "\"" & ", sig=\"" & sig & "\""

  echo "3.AUTHORIZATION"
  echo authHeader

  let resp = await HttpClientRequestRef.post(HttpSessionRef.new(), registrationURL, body = $payload, headers = [
      ("Content-Type", "application/json"),
      ("User-Agent", "nim-libp2p"),
      ("authorization", authHeader),
    ],
  ).get().send()

  echo "4.SERVER BEARER"
  echo resp.status
  echo bytesToString(await resp.getBodyBytes())
  echo resp.headers

  result = extractField(resp.headers.getString("authentication-info"), "bearer")

proc encodePeerId(peerId: PeerId): string =
  var mh: MultiHash
  if MultiHash.decode(peerId.data, mh).get() == -1:
      echo "error! wrong multihash"
      quit(1)
  # cidv1 from multihash with libp2pkey codec
  let cid = Cid.init(CIDv1, multiCodec("libp2p-key"), mh).get()
  return Base36.encode(cid.data.buffer)

proc urandomToCString(len: int): cstring =
  let randBytes = urandom(len)
  result = cast[cstring](alloc(len + 1))  # +1 for null terminator
  for i in 0..<len:
    result[i] = char(randBytes[i])
  result[len] = '\0'  # Null-terminate

proc main() {.async: (raises: [Exception]).} =
  # if key file does not exist, register account
  let keyFile = "/tmp/account.key"
  var account: Account = newAccount()
  if fileExists(keyFile):
    account.privKey = readFile(keyFile)
  else:
    writeFile(keyFile, account.privKey)
  await account.registerAccount()
  # registering account with key already present returns account

  # start libp2p peer
  let rng = newRng()
  let switch = SwitchBuilder
    .new()
    .withRng(rng)
    .withAddress(MultiAddress.init("/ip4/0.0.0.0/tcp/0").tryGet())
    .withTcpTransport()
    .withYamux()
    .withNoise()
    .build()
  await switch.start()

  let base36PeerId = encodePeerId(switch.peerInfo.peerId)
  echo base36PeerId

  # this will be the domain we're issuing a certificate for
  let baseDomain = fmt"{base36PeerId}.{AutoTLSDNSServer}"
  let domain = fmt"*.{baseDomain}"

  # request challenge from CA
  let (dns01Challenge, finalizeURL) = await account.requestChallenge(@[domain])
  echo fmt"challenge: {dns01Challenge}"

  let key = loadRsaKey(account.privKey)

  let keyAuthorization = base64UrlEncode(
    @(
      sha256.digest((dns01Challenge["token"].getStr & "." & thumbprint(key)).toByteSeq).data
    )
  )
  echo fmt"key authorization: {keyAuthorization}"

  # authenticate and send challenge to AutoTLS broker
  var multiaddrs: seq[string] = @[]
  for ma in switch.peerInfo.addrs:
    multiaddrs.add($ma)

  let payload = %*{"value": keyAuthorization, "addresses": multiaddrs}
  echo "payload: ", $payload
  # authenticate as peerID with AutoTLS broker and send challenge
  # https://github.com/libp2p/specs/blob/master/http/peer-id-auth.md
  let bearerToken = await peerIDAuth(
    base36PeerId, switch.peerInfo.privateKey, switch.peerInfo.publicKey,
    payload,
  )
  discard bearerToken

  # check for TXT RR {peerId}.libp2p.direct (base36 encoded peerid)
  let dashedIpAddr = ($getPrimaryIPAddr()).replace(".", "-")
  echo dashedIpAddr
  echo execCmdEx(fmt"dig TXT _acme-challenge.{baseDomain}")
  echo execCmdEx(fmt"dig A {dashedIpAddr}.{baseDomain}")
  echo ""

  # notify ACME server of challenge completion (signed req with empty payload)
  let chalURL = dns01Challenge["url"].getStr
  let emptyPayload = newJObject()
  let completedResp = await account.makeSignedAcmeRequest(chalURL, emptyPayload)
  let resp_body = bytesToString(await completedResp.getBodyBytes())
  echo resp_body
  let completedBody = resp_body.parseJson()

  # check until acme server is done (poll validation)
  let checkURL = completedBody["url"].getStr
  var chalCompleted = false
  while (not chalCompleted):
    let checkResp = await HttpClientRequestRef.get(HttpSessionRef.new(), checkURL).get().send()
    let checkBody = bytesToString(await checkResp.getBodyBytes())
    let checkJson = checkBody.parseJson()
    if checkJson["status"].getStr != "pending":
        echo checkBody
        chalCompleted = true

  # finalize the request
  var certKey: cert_key_t
  var certCtx: cert_context_t
  let randomCstring = urandomToCString(256)
  if cert_init_drbg(randomCstring, 256, certCtx.addr) != CERT_SUCCESS:
    echo fmt"error initializing context"
    quit(1)
  if cert_generate_key(certCtx, certKey.addr) != CERT_SUCCESS:
    echo fmt"error generating key"
    quit(1)
  var derCSR: ptr cert_buffer = nil

  let requestingDomainCstr = (fmt"*.{baseDomain}").cstring
  echo requestingDomainCstr
  let errCode = cert_signing_req(requestingDomainCstr, certKey, derCSR.addr)
  echo fmt"here3: error code: {errCode}"
  # TODO: convert dercsr to bytes (toseq does not work)
  let b64CSR = base64UrlEncodeNoSuffix(derCSR.toSeq)
  var certFinalized = false
  while (not certFinalized):
    let finalizedResp = await account.makeSignedAcmeRequest(finalizeURL, %*{"csr": b64CSR})
    let finalizedBody = bytesToString(await finalizedResp.getBodyBytes()).parseJson()
    echo finalizedBody
    if finalizedBody["status"].getStr != "processing":
      certFinalized = true

  await switch.stop()

waitFor(main())
