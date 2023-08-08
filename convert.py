import base64
import json
import random
import string
import sys
import typing
import uuid
from urllib.parse import quote

import httpx


class Protocols:
    VMESS = "vmess"
    VLESS = "vless"
    TROJAN = "trojan"
    SHADOWSOCKS = "shadowsocks"
    DOKODEMO = "dokodemo-door"
    MTPROTO = "mtproto"
    SOCKS = "socks"
    HTTP = "http"


class VmessMethods:
    AES_128_GCM = "aes-128-gcm"
    CHACHA20_POLY1305 = "chacha20-poly1305"
    AUTO = "auto"
    NONE = "none"


class SSMethods:
    # AES_256_CFB = 'aes-256-cfb'
    # AES_128_CFB = 'aes-128-cfb'
    # CHACHA20 = 'chacha20'
    # CHACHA20_IETF = 'chacha20-ietf'
    CHACHA20_POLY1305 = "chacha20-poly1305"
    AES_256_GCM = "aes-256-gcm"
    AES_128_GCM = "aes-128-gcm"


class RULE_IP:
    PRIVATE = "geoip:private"
    CN = "geoip:cn"


class RULE_DOMAIN:
    ADS = "geosite:category-ads"
    ADS_ALL = "geosite:category-ads-all"
    CN = "geosite:cn"
    GOOGLE = "geosite:google"
    FACEBOOK = "geosite:facebook"
    SPEEDTEST = "geosite:speedtest"


class FLOW_CONTROL:
    ORIGIN = "xtls-rprx-origin"
    DIRECT = "xtls-rprx-direct"


seq = list(string.ascii_lowercase + string.digits + string.ascii_uppercase)


class RandomUtil:
    @staticmethod
    def random_int_range(min_val, max_val):
        return random.randint(min_val, max_val)

    @staticmethod
    def random_int(n):
        return RandomUtil.random_int_range(0, n)

    @staticmethod
    def random_seq(count):
        return "".join(random.choice(seq) for _ in range(count))

    @staticmethod
    def random_lower_and_num(count):
        return "".join(random.choice(seq[:36]) for _ in range(count))

    @staticmethod
    def random_mt_secret():
        return "".join(
            str(random.choice(range(10))) if i <= 9 else random.choice(seq[10:36])
            for i in range(32)
        )

    @staticmethod
    def random_uuid():
        return str(uuid.uuid4())


class XrayCommonClass:
    @staticmethod
    def to_json_array(arr):
        return [obj.to_json() for obj in arr]

    @staticmethod
    def from_json():
        return XrayCommonClass()

    def to_json(self):
        raise NotImplementedError()

    def to_string(self, format=True):
        return json.dumps(self.to_json(), indent=2 if format else None)

    @staticmethod
    def to_headers(v2Headers):
        newHeaders = []
        if v2Headers:
            for key, values in v2Headers.items():
                if isinstance(values, str):
                    newHeaders.append({"name": key, "value": values})
                else:
                    for value in values:
                        newHeaders.append({"name": key, "value": value})
        return newHeaders

    @staticmethod
    def to_v2_headers(headers, arr=True):
        v2Headers = {}
        for header in headers:
            name = header["name"]
            value = header["value"]
            if name is None or value is None:
                continue
            if name not in v2Headers:
                v2Headers[name] = [value] if arr else value
            else:
                if arr:
                    v2Headers[name].append(value)
                else:
                    v2Headers[name] = value
        return v2Headers


class TcpStreamSettings(XrayCommonClass):
    def __init__(
        self, acceptProxyProtocol=False, type="none", request=None, response=None
    ):
        super().__init__()
        self.acceptProxyProtocol = acceptProxyProtocol
        self.type = type
        self.request = request if request is not None else TcpRequest()
        self.response = response if response is not None else TcpResponse()

    @staticmethod
    def from_json(json={}):
        if json is None:
            json = {}
        header = json.get("header", {})
        return TcpStreamSettings(
            json.get("acceptProxyProtocol", False),
            header.get("type", "none"),
            TcpRequest.from_json(header.get("request", {})),
            TcpResponse.from_json(header.get("response", {})),
        )

    def to_json(self):
        return {
            "acceptProxyProtocol": self.acceptProxyProtocol,
            "header": {
                "type": self.type,
                "request": self.request.to_json() if self.type == "http" else None,
                "response": self.response.to_json() if self.type == "http" else None,
            },
        }


class TcpRequest(XrayCommonClass):
    def __init__(self, version="1.1", method="GET", path=["/"], headers=[]):
        super().__init__()
        self.version = version
        self.method = method
        self.path = path if len(path) > 0 else ["/"]
        self.headers: typing.List[typing.Dict[str, str]] = headers

    def addPath(self, path):
        self.path.append(path)

    def removePath(self, index):
        self.path.pop(index)

    def addHeader(self, name, value):
        self.headers.append({"name": name, "value": value})

    def getHeader(self, name):
        for header in self.headers:
            if header["name"].lower() == name.lower():
                return header["value"]
        return None

    def removeHeader(self, index):
        self.headers.pop(index)

    @staticmethod
    def from_json(json={}):
        return TcpRequest(
            json.get("version", "1.1"),
            json.get("method", "GET"),
            json.get("path", ["/"]),
            XrayCommonClass.to_headers(json.get("headers", {})),
        )

    def to_json(self):
        return {
            "method": self.method,
            "path": self.path.copy(),
            "headers": XrayCommonClass.to_v2_headers(self.headers),
        }


class TcpResponse(XrayCommonClass):
    def __init__(self, version="1.1", status="200", reason="OK", headers=[]):
        super().__init__()
        self.version = version
        self.status = status
        self.reason = reason
        self.headers: typing.List[typing.Dict[str, str]] = headers

    def addHeader(self, name, value):
        self.headers.append({"name": name, "value": value})

    def removeHeader(self, index):
        self.headers.pop(index)

    @staticmethod
    def from_json(json={}):
        return TcpResponse(
            json.get("version", "1.1"),
            json.get("status", "200"),
            json.get("reason", "OK"),
            XrayCommonClass.to_headers(json.get("headers", {})),
        )

    def to_json(self):
        return {
            "version": self.version,
            "status": self.status,
            "reason": self.reason,
            "headers": XrayCommonClass.to_v2_headers(self.headers),
        }


class KcpStreamSettings(XrayCommonClass):
    def __init__(
        self,
        mtu=1350,
        tti=20,
        uplinkCapacity=5,
        downlinkCapacity=20,
        congestion=False,
        readBufferSize=2,
        writeBufferSize=2,
        type="none",
        seed=RandomUtil.random_seq(10),
    ):
        super().__init__()
        self.mtu = mtu
        self.tti = tti
        self.upCap = uplinkCapacity
        self.downCap = downlinkCapacity
        self.congestion = congestion
        self.readBuffer = readBufferSize
        self.writeBuffer = writeBufferSize
        self.type = type
        self.seed = seed

    @staticmethod
    def from_json(json={}):
        if json is None:
            json = {}
        return KcpStreamSettings(
            json.get("mtu", 1350),
            json.get("tti", 20),
            json.get("uplinkCapacity", 5),
            json.get("downlinkCapacity", 20),
            json.get("congestion", False),
            json.get("readBufferSize", 2),
            json.get("writeBufferSize", 2),
            "none"
            if json.get("header") is None
            else json["header"].get("type", "none"),
            json.get("seed", RandomUtil.random_seq(10)),
        )

    def to_json(self):
        return {
            "mtu": self.mtu,
            "tti": self.tti,
            "uplinkCapacity": self.upCap,
            "downlinkCapacity": self.downCap,
            "congestion": self.congestion,
            "readBufferSize": self.readBuffer,
            "writeBufferSize": self.writeBuffer,
            "header": {
                "type": self.type,
            },
            "seed": self.seed,
        }


class WsStreamSettings(XrayCommonClass):
    def __init__(self, acceptProxyProtocol=False, path="/", headers=[]):
        super().__init__()
        self.acceptProxyProtocol = acceptProxyProtocol
        self.path: str = path
        self.headers: typing.List[typing.Dict[str, str]] = headers

    def addHeader(self, name, value):
        self.headers.append({"name": name, "value": value})

    def getHeader(self, name):
        for header in self.headers:
            if header["name"].lower() == name.lower():
                return header["value"]
        return None

    def removeHeader(self, index):
        self.headers.pop(index)

    @staticmethod
    def from_json(json={}):
        if json is None:
            json = {}
        return WsStreamSettings(
            json.get("acceptProxyProtocol", False),
            json.get("path", "/"),
            XrayCommonClass.to_headers(json.get("headers", [])),
        )

    def to_json(self):
        return {
            "acceptProxyProtocol": self.acceptProxyProtocol,
            "path": self.path,
            "headers": XrayCommonClass.to_v2_headers(self.headers, False),
        }


class HttpStreamSettings(XrayCommonClass):
    def __init__(self, path="/", host=[""]):
        super().__init__()
        self.path = path
        self.host = host if len(host) > 0 else [""]

    def addHost(self, host):
        self.host.append(host)

    def removeHost(self, index):
        self.host.pop(index)

    @staticmethod
    def from_json(json={}):
        if json is None:
            json = {}
        return HttpStreamSettings(json.get("path", "/"), json.get("host", [""]))

    def to_json(self):
        host = [h for h in self.host if h]
        return {
            "path": self.path,
            "host": host,
        }


class QuicStreamSettings(XrayCommonClass):
    def __init__(self, security=VmessMethods.NONE, key="", type="none"):
        super().__init__()
        self.security = security
        self.key = key
        self.type = type

    @staticmethod
    def from_json(json={}):
        if json is None:
            json = {}
        return QuicStreamSettings(
            json.get("security", VmessMethods.NONE),
            json.get("key", ""),
            json.get("header", {}).get("type", "none"),
        )

    def to_json(self):
        return {
            "security": self.security,
            "key": self.key,
            "header": {
                "type": self.type,
            },
        }


class GrpcStreamSettings(XrayCommonClass):
    def __init__(self, service_name=""):
        super().__init__()
        self.service_name = service_name

    @staticmethod
    def from_json(json={}):
        if json is None:
            json = {}
        return GrpcStreamSettings(json.get("serviceName", ""))

    def to_json(self):
        return {
            "serviceName": self.service_name,
        }


class TlsStreamSettingsCert(XrayCommonClass):
    def __init__(
        self, use_file=True, certificate_file="", key_file="", certificate="", key=""
    ):
        super().__init__()
        self.use_file = use_file
        self.cert_file = certificate_file
        self.key_file = key_file
        self.cert = (
            "\n".join(certificate) if isinstance(certificate, list) else certificate
        )
        self.key = "\n".join(key) if isinstance(key, list) else key

    @staticmethod
    def from_json(json={}):
        if "certificateFile" in json and "keyFile" in json:
            return TlsStreamSettingsCert(
                True,
                json.get("certificateFile", ""),
                json.get("keyFile", ""),
            )
        else:
            return TlsStreamSettingsCert(
                False,
                "",
                "",
                "\n".join(json.get("certificate", [])),
                "\n".join(json.get("key", [])),
            )

    def to_json(self):
        if self.use_file:
            return {
                "certificateFile": self.cert_file,
                "keyFile": self.key_file,
            }
        else:
            return {
                "certificate": self.cert.split("\n"),
                "key": self.key.split("\n"),
            }


class TlsStreamSettings(XrayCommonClass):
    def __init__(self, server_name="", certificates=[TlsStreamSettingsCert()], alpn=[]):
        super().__init__()
        self.server = server_name
        self.certs = certificates
        self.alpn = alpn

    def add_cert(self, cert):
        self.certs.append(cert)

    def remove_cert(self, index):
        self.certs.pop(index)

    @staticmethod
    def from_json(json={}):
        if json is None:
            json = {}
        certs = []
        if "certificates" in json and isinstance(json["certificates"], list):
            certs = [
                TlsStreamSettingsCert.from_json(cert) for cert in json["certificates"]
            ]

        return TlsStreamSettings(
            json.get("serverName", ""), certs, json.get("alpn", [])
        )

    def to_json(self):
        return {
            "serverName": self.server,
            "certificates": [cert.to_json() for cert in self.certs],
            "alpn": self.alpn,
        }


class StreamSettings(XrayCommonClass):
    def __init__(
        self,
        network="tcp",
        security="none",
        tls_settings=None,
        tcp_settings=None,
        kcp_settings=None,
        ws_settings=None,
        http_settings=None,
        quic_settings=None,
        grpc_settings=None,
    ):
        super().__init__()
        self.network = network
        self.security = security
        self.tls: "TlsStreamSettings" = (
            tls_settings if tls_settings is not None else TlsStreamSettings()
        )
        self.tcp: "TcpStreamSettings" = (
            tcp_settings if tcp_settings is not None else TcpStreamSettings()
        )
        self.kcp: "KcpStreamSettings" = (
            kcp_settings if kcp_settings is not None else KcpStreamSettings()
        )
        self.ws: "WsStreamSettings" = (
            ws_settings if ws_settings is not None else WsStreamSettings()
        )
        self.http: "HttpStreamSettings" = (
            http_settings if http_settings is not None else HttpStreamSettings()
        )
        self.quic: "QuicStreamSettings" = (
            quic_settings if quic_settings is not None else QuicStreamSettings()
        )
        self.grpc: "GrpcStreamSettings" = (
            grpc_settings if grpc_settings is not None else GrpcStreamSettings()
        )

    @property
    def is_tls(self):
        return self.security == "tls"

    @is_tls.setter
    def is_tls(self, is_tls):
        if is_tls:
            self.security = "tls"
        else:
            self.security = "none"

    @property
    def is_xtls(self):
        return self.security == "xtls"

    @is_xtls.setter
    def is_xtls(self, is_xtls):
        if is_xtls:
            self.security = "xtls"
        else:
            self.security = "none"

    @staticmethod
    def from_json(json_data=None):
        if not json_data:
            json_data = {}
        tls_settings = (
            TlsStreamSettings.from_json(json_data.get("xtlsSettings"))
            if json_data.get("security") == "xtls"
            else TlsStreamSettings.from_json(json_data.get("tlsSettings"))
        )
        return StreamSettings(
            json_data.get("network"),
            json_data.get("security"),
            tls_settings,
            TcpStreamSettings.from_json(json_data.get("tcpSettings")),
            KcpStreamSettings.from_json(json_data.get("kcpSettings")),
            WsStreamSettings.from_json(json_data.get("wsSettings")),
            HttpStreamSettings.from_json(json_data.get("httpSettings")),
            QuicStreamSettings.from_json(json_data.get("quicSettings")),
            GrpcStreamSettings.from_json(json_data.get("grpcSettings")),
        )

    def to_json(self):
        json_data = {
            "network": self.network,
            "security": self.security,
            "tlsSettings": self.tls.to_json() if self.is_tls else None,
            "xtlsSettings": self.tls.to_json() if self.is_xtls else None,
            "tcpSettings": self.tcp.to_json() if self.network == "tcp" else None,
            "kcpSettings": self.kcp.to_json() if self.network == "kcp" else None,
            "wsSettings": self.ws.to_json() if self.network == "ws" else None,
            "httpSettings": self.http.to_json() if self.network == "http" else None,
            "quicSettings": self.quic.to_json() if self.network == "quic" else None,
            "grpcSettings": self.grpc.to_json() if self.network == "grpc" else None,
        }
        return json_data


class Sniffing(XrayCommonClass):
    def __init__(self, enabled=True, dest_override=["http", "tls"]):
        super().__init__()
        self.enabled = enabled
        self.dest_override = dest_override

    @staticmethod
    def from_json(json={}):
        dest_override = json.get("destOverride", [])
        if dest_override and isinstance(dest_override, list) and not all(dest_override):
            dest_override = ["http", "tls"]
        return Sniffing(
            bool(json.get("enabled", True)),
            dest_override,
        )

    def to_json(self):
        return {
            "enabled": self.enabled,
            "destOverride": self.dest_override,
        }


class Inbound(XrayCommonClass):
    def __init__(
        self,
        port=None,
        listen="",
        protocol=Protocols.VMESS,
        settings=None,
        stream_settings=StreamSettings(),
        tag="",
        sniffing=Sniffing(),
    ):
        super().__init__()
        self.port = (
            port if port is not None else RandomUtil.random_int_range(10000, 60000)
        )
        self.listen: str = listen
        self._protocol: "Protocols" = protocol
        self.settings: typing.Union[
            "InboundVmessSettings",
            "InboundVLESSSettings",
            "InboundTrojanSettings",
            "InboundShadowsocksSettings",
            "InboundDokodemoSettings",
            "InboundMtprotoSettings",
            "InboundSocksSettings",
            "InboundHttpSettings",
        ] = (
            settings if settings is not None else InboundSettings.get_settings(protocol)
        )
        self.stream: "StreamSettings" = stream_settings
        self.tag: str = tag
        self.sniffing: "Sniffing" = sniffing

    @property
    def protocol(self):
        return self._protocol

    @protocol.setter
    def protocol(self, protocol):
        self._protocol = protocol
        self.settings = InboundSettings.get_settings(protocol)
        if protocol == Protocols.TROJAN:
            self.tls = True

    @property
    def tls(self):
        return self.stream.security == "tls"

    @tls.setter
    def tls(self, is_tls):
        self.stream.security = "tls" if is_tls else "none"

    @property
    def xtls(self):
        return self.stream.security == "xtls"

    @xtls.setter
    def xtls(self, is_xtls):
        self.stream.security = "xtls" if is_xtls else "none"

    @property
    def network(self):
        return self.stream.network

    @network.setter
    def network(self, network):
        self.stream.network = network

    @property
    def is_tcp(self):
        return self.network == "tcp"

    @property
    def is_ws(self):
        return self.network == "ws"

    @property
    def is_kcp(self):
        return self.network == "kcp"

    @property
    def is_quic(self):
        return self.network == "quic"

    @property
    def is_grpc(self):
        return self.network == "grpc"

    @property
    def is_h2(self):
        return self.network == "http"

    # VMess & VLess
    @property
    def uuid(self):
        """只有 VMess 和 VLess 协议有 uuid 属性"""
        if self.protocol == Protocols.VMESS:
            return self.settings.vmesses[0].id
        elif self.protocol == Protocols.VLESS:
            return self.settings.vlesses[0].id
        else:
            return ""

    # VLess & Trojan
    @property
    def flow(self):
        """只有 VLess 和 Trojan 协议有 flow 属性"""
        if self.protocol == Protocols.VLESS:
            return self.settings.vlesses[0].flow
        elif self.protocol == Protocols.TROJAN:
            return self.settings.clients[0].flow
        else:
            return ""

    # VMess
    @property
    def alterId(self):
        """只有 VMess 协议有 alterId 属性"""
        if self.protocol == Protocols.VMESS:
            return self.settings.vmesses[0].alter_id
        else:
            return ""

    # Socks & HTTP
    @property
    def username(self):
        """以下几种协议都有 username 属性
        - Socks
        - HTTP
        """

        if self.protocol in (Protocols.SOCKS, Protocols.HTTP):
            if not self.settings.accounts:
                return ""
            return self.settings.accounts[0].user
        else:
            return ""

    # Trojan & Shadowsocks & Socks & HTTP
    @property
    def password(self):
        """以下几种协议都有 password 属性
        - Trojan
        - Shadowsocks
        - Socks
        - HTTP
        """

        if self.protocol == Protocols.TROJAN:
            if not self.settings.clients:
                return ""
            return self.settings.clients[0].password
        elif self.protocol == Protocols.SHADOWSOCKS:
            return self.settings.password
        elif self.protocol in (Protocols.SOCKS, Protocols.HTTP):
            if not self.settings.accounts:
                return ""
            return self.settings.accounts[0].password
        else:
            return ""

    # Shadowsocks
    @property
    def method(self):
        if self.protocol == Protocols.SHADOWSOCKS:
            return self.settings.method
        else:
            return ""

    @property
    def serverName(self):
        if self.stream.is_tls or self.stream.is_xtls:
            return self.stream.tls.server
        return ""

    @property
    def host(self):
        if self.is_tcp:
            return self.stream.tcp.request.getHeader("Host")
        elif self.is_ws:
            return self.stream.ws.getHeader("Host")
        elif self.is_h2:
            return self.stream.http.host[0]
        return None

    @property
    def path(self):
        if self.is_tcp:
            return self.stream.tcp.request.path[0]
        elif self.is_ws:
            return self.stream.ws.path
        elif self.is_h2:
            return self.stream.http.path[0]
        return None

    @property
    def quicSecurity(self):
        return self.stream.quic.security

    @property
    def quicKey(self):
        return self.stream.quic.key

    @property
    def quicType(self):
        return self.stream.quic.type

    @property
    def kcpType(self):
        return self.stream.kcp.type

    @property
    def kcpSeed(self):
        return self.stream.kcp.seed

    @property
    def serviceName(self):
        return self.stream.grpc.service_name

    def canEnableTls(self):
        return self.protocol in (
            Protocols.VMESS,
            Protocols.VLESS,
            Protocols.TROJAN,
            Protocols.SHADOWSOCKS,
        ) and self.network in ("tcp", "ws", "http", "quic", "grpc")

    def canSetTls(self):
        return self.canEnableTls()

    def canEnableXTls(self):
        return (
            self.protocol in (Protocols.VLESS, Protocols.TROJAN)
            and self.network == "tcp"
        )

    def canEnableStream(self):
        return self.protocol in (
            Protocols.VMESS,
            Protocols.VLESS,
            Protocols.SHADOWSOCKS,
        )

    def canSniffing(self):
        return self.protocol in (
            Protocols.VMESS,
            Protocols.VLESS,
            Protocols.TROJAN,
            Protocols.SHADOWSOCKS,
        )

    def reset(self):
        self.port = RandomUtil.random_int_range(10000, 60000)
        self.listen = ""
        self.protocol = Protocols.VMESS
        self.settings = InboundSettings.get_settings(Protocols.VMESS)
        self.stream: "StreamSettings" = StreamSettings()
        self.tag = ""
        self.sniffing = Sniffing()

    def genVmessLink(self, address="", remark=""):
        if self.protocol != Protocols.VMESS:
            return ""

        network = self.stream.network
        type_ = "none"
        host = ""
        path = ""
        if network == "tcp":
            tcp = self.stream.tcp
            type_ = tcp.type
            if type_ == "http":
                request = tcp.request
                path = ",".join(request.path)
                index = next(
                    (
                        i
                        for i, header in enumerate(request.headers)
                        if header["name"].lower() == "host"
                    ),
                    -1,
                )
                if index >= 0:
                    host = request.headers[index]["value"]
        elif network == "kcp":
            kcp = self.stream.kcp
            type_ = kcp.type
            path = kcp.seed
        elif network == "ws":
            ws = self.stream.ws
            path = ws.path
            index = next(
                (
                    i
                    for i, header in enumerate(ws.headers)
                    if header["name"].lower() == "host"
                ),
                -1,
            )
            if index >= 0:
                host = ws.headers[index]["value"]
        elif network == "http":
            network = "h2"
            path = self.stream.http.path
            host = ",".join(self.stream.http.host)
        elif network == "quic":
            type_ = self.stream.quic.type
            host = self.stream.quic.security
            path = self.stream.quic.key
        elif network == "grpc":
            path = self.stream.grpc.service_name

        if self.stream.security == "tls":
            if self.stream.tls.server:
                address = self.stream.tls.server

        obj = {
            "v": "2",
            "ps": remark,
            "add": address,
            "port": self.port,
            "id": self.settings.vmesses[0].id,
            "aid": self.settings.vmesses[0].alter_id,
            "net": network,
            "type": type_,
            "host": host,
            "path": path,
            "tls": self.stream.security,
        }
        return (
            "vmess://"
            + base64.urlsafe_b64encode(json.dumps(obj, indent=2).encode()).decode()
        )

    def genVLESSLink(self, address="", remark=""):
        settings = self.settings
        uuid = settings.vlesses[0].id
        port = self.port
        type_ = self.stream.network
        params = {}
        params["type"] = self.stream.network
        if self.xtls:
            params["security"] = "xtls"
        else:
            params["security"] = self.stream.security

        if type_ == "tcp":
            tcp = self.stream.tcp
            if tcp.type == "http":
                request = tcp.request
                params["path"] = ",".join(request.path)
                index = next(
                    (
                        i
                        for i, header in enumerate(request.headers)
                        if header["name"].lower() == "host"
                    ),
                    -1,
                )
                if index >= 0:
                    host = request.headers[index]["value"]
                    params["host"] = host
        elif type_ == "kcp":
            kcp = self.stream.kcp
            params["headerType"] = kcp.type
            params["seed"] = kcp.seed
        elif type_ == "ws":
            ws = self.stream.ws
            params["path"] = ws.path
            index = next(
                (
                    i
                    for i, header in enumerate(ws.headers)
                    if header["name"].lower() == "host"
                ),
                -1,
            )
            if index >= 0:
                host = ws.headers[index]["value"]
                params["host"] = host
        elif type_ == "http":
            http = self.stream.http
            params["path"] = http.path
            params["host"] = http.host[0]
        elif type_ == "quic":
            quic = self.stream.quic
            params["quicSecurity"] = quic.security
            params["key"] = quic.key
            params["headerType"] = quic.type
        elif type_ == "grpc":
            grpc = self.stream.grpc
            params["serviceName"] = grpc.service_name

        if self.stream.security == "tls":
            if self.stream.tls.server:
                address = self.stream.tls.server
                params["sni"] = address

        if self.xtls:
            params["flow"] = self.settings.vlesses[0].flow

        return str(
            httpx.URL(
                scheme="vless",
                userinfo=quote(uuid).encode(),
                host=address,
                port=port,
                params=params,
                fragment=remark if remark else None,
            )
        )

    def genSSLink(self, address="", remark=""):
        settings = self.settings
        server = self.stream.tls.server
        if server:
            address = server
        return (
            "ss://"
            + base64.urlsafe_b64encode(
                str(
                    httpx.URL(
                        scheme="",
                        username=settings.method,
                        password=settings.password,
                        host=address,
                        port=self.port,
                        fragment=remark if remark else None,
                    )
                )
                .removeprefix("//")
                .encode()
            ).decode()
        )

    def genTrojanLink(self, address="", remark=""):
        settings = self.settings
        return str(
            httpx.URL(
                scheme="trojan",
                userinfo=quote(settings.clients[0].password).encode(),
                host=address,
                port=self.port,
                fragment=remark if remark else None,
            )
        )

    def genSocksLink(self, address="", remark=""):
        # 如果有认证信息，使用 socks5://user:pass@host:port#remark
        # 如果没有认证信息，使用 socks5://host:port#remark
        if self.settings.accounts:
            return str(
                httpx.URL(
                    scheme="socks5h",
                    username=self.username,
                    password=self.password,
                    host=address,
                    port=self.port,
                    fragment=remark if remark else None,
                )
            )
        else:
            return str(
                httpx.URL(
                    scheme="socks5h",
                    host=address,
                    port=self.port,
                    fragment=remark if remark else None,
                )
            )

    def genHttpLink(self, address="", remark=""):
        # 如果有认证信息，使用 http://user:pass@host:port#remark
        # 如果没有认证信息，使用 http://host:port#remark
        # 如果是https，设置scheme为https
        if self.settings.accounts:
            return str(
                httpx.URL(
                    scheme="https" if self.stream.is_tls else "http",
                    username=self.username,
                    password=self.password,
                    host=address,
                    port=self.port,
                    fragment=remark if remark else None,
                )
            )
        else:
            return str(
                httpx.URL(
                    scheme="https" if self.stream.is_tls else "http",
                    host=address,
                    port=self.port,
                    fragment=remark if remark else None,
                )
            )

    def genLink(self, address="", remark=""):
        switcher = {
            Protocols.VMESS: self.genVmessLink,
            Protocols.VLESS: self.genVLESSLink,
            Protocols.SHADOWSOCKS: self.genSSLink,
            Protocols.TROJAN: self.genTrojanLink,
            Protocols.SOCKS: self.genSocksLink,
            Protocols.HTTP: self.genHttpLink,
        }
        gen_func = switcher.get(self.protocol, lambda x, y: "")
        return gen_func(address, remark)

    def genVmessSurge(self, address="", remark=""):
        if self.protocol != Protocols.VMESS:
            return ""
        network = self.stream.network
        addition = ""
        if network == "ws":
            ws = self.stream.ws
            path = ws.path
            headers = ""
            for header in ws.headers:
                # todo: 如果value中有引号和逗号，需要转义
                headers += f"{header['name']}=\"{header['value']}\"|"
            if headers:
                headers = headers[:-1]
            # ws support ws, ws-path, ws-headers, encrypt-method
            addition = f", ws=true, ws-path={path}, ws-headers={headers}"
        elif network == "quic":
            return ""
        elif network == "grpc":
            return ""

        # sample return: ProxyVMess = vmess, 1.2.3.4, 8000, username=0233d11c-15a4-47d3-ade3-48ffca0ce119
        return f"{remark} = vmess, {address}, {self.port}, username={self.uuid}" + addition

    def genSSSurge(self, address="", remark=""):
        settings = self.settings
        server = self.stream.tls.server
        if server:
            address = server
        # sample return: ProxySS = ss, 1.2.3.4, 8000, encrypt-method=chacha20-ietf-poly1305, password=abcd1234
        return f"{remark} = ss, {address}, {self.port}, encrypt-method={settings.method}, password={settings.password}, udp-relay=true"

    def genTrojanSurge(self, address="", remark=""):
        settings = self.settings
        # sample return: ProxyTrojan = trojan, 192.168.20.6, 443, password=password1
        return f"{remark} = trojan, {address}, {self.port}, password={settings.clients[0].password}"

    def genSocksSurge(self, address="", remark=""):
        # ProxySOCKS5 = socks5, 1.2.3.4, 443, username, password
        # ProxySOCKS5TLS = socks5-tls, 1.2.3.4, 443, username, password, skip-common-name-verify=true
        if self.tls:
            return f"{remark} = socks5-tls, {address}, {self.port}, {self.username}, {self.password}, skip-common-name-verify=true, udp-relay=true"
        else:
            return f"{remark} = socks5, {address}, {self.port}, {self.username}, {self.password}, udp-relay=true"
            

    def genHttpSurge(self, address="", remark=""):
        # 以下是HTTP和HTTPS两种示例返回
        # ProxyHTTP = http, 1.2.3.4, 443, username, password
        # ProxyHTTPS = https, 1.2.3.4, 443, username, password
        if self.tls:
            return f"{remark} = https, {address}, {self.port}, {self.username}, {self.password}"
        else:
            return f"{remark} = http, {address}, {self.port}, {self.username}, {self.password}"


    def genSurge(self, address="", remark=""):
        switcher = {
            Protocols.VMESS: self.genVmessSurge,
            Protocols.SHADOWSOCKS: self.genSSSurge,
            Protocols.TROJAN: self.genTrojanSurge,
            Protocols.SOCKS: self.genSocksSurge,
            Protocols.HTTP: self.genHttpSurge,
        }
        gen_func = switcher.get(self.protocol, lambda x, y: "")
        return gen_func(address, remark)

    def genVmessClashProfile(self, address, remark):
        """
        type RealityOptions struct {
            PublicKey string `proxy:"public-key"`
            ShortID   string `proxy:"short-id"`
        }
        type HTTPOptions struct {
            Method  string              `proxy:"method,omitempty"`
            Path    []string            `proxy:"path,omitempty"`
            Headers map[string][]string `proxy:"headers,omitempty"`
        }
        type HTTP2Options struct {
            Host []string `proxy:"host,omitempty"`
            Path string   `proxy:"path,omitempty"`
        }
        type GrpcOptions struct {
            GrpcServiceName string `proxy:"grpc-service-name,omitempty"`
        }
        type WSOptions struct {
            Path                string            `proxy:"path,omitempty"`
            Headers             map[string]string `proxy:"headers,omitempty"`
            MaxEarlyData        int               `proxy:"max-early-data,omitempty"`
            EarlyDataHeaderName string            `proxy:"early-data-header-name,omitempty"`
        }

        Name                string         `proxy:"name"`
        Server              string         `proxy:"server"`
        Port                int            `proxy:"port"`
        UUID                string         `proxy:"uuid"`
        AlterID             int            `proxy:"alterId"`
        Cipher              string         `proxy:"cipher"`
        UDP                 bool           `proxy:"udp,omitempty"`
        Network             string         `proxy:"network,omitempty"`
        TLS                 bool           `proxy:"tls,omitempty"`
        SkipCertVerify      bool           `proxy:"skip-cert-verify,omitempty"`
        Fingerprint         string         `proxy:"fingerprint,omitempty"`
        ServerName          string         `proxy:"servername,omitempty"`
        RealityOpts         RealityOptions `proxy:"reality-opts,omitempty"`
        HTTPOpts            HTTPOptions    `proxy:"http-opts,omitempty"`
        HTTP2Opts           HTTP2Options   `proxy:"h2-opts,omitempty"`
        GrpcOpts            GrpcOptions    `proxy:"grpc-opts,omitempty"`
        WSOpts              WSOptions      `proxy:"ws-opts,omitempty"`
        PacketAddr          bool           `proxy:"packet-addr,omitempty"`
        XUDP                bool           `proxy:"xudp,omitempty"`
        PacketEncoding      string         `proxy:"packet-encoding,omitempty"`
        GlobalPadding       bool           `proxy:"global-padding,omitempty"`
        AuthenticatedLength bool           `proxy:"authenticated-length,omitempty"`
        ClientFingerprint   string         `proxy:"client-fingerprint,omitempty"`
        """
        if self.stream.tcp.request.headers and self.stream.network == "http":
            sys.stderr.write(str(self.stream.tcp.request.headers) + "\n")
        data = {
            "name": remark,
            "server": address,
            "port": self.port,
            "uuid": self.uuid,
            "alterId": self.alterId,
            "cipher": "auto",
            "network": self.stream.network,
            "tls": self.stream.security != "none",
            "skip-cert-verify": True,
            "servername": self.serverName,
            # "h2-opts": {
            #     "host": [self.stream.tcp.request.getHeader("Host")],
            #     "path": "".join(self.stream.tcp.request.path),
            # },
        }
        if self.stream.network == "http":
            data["http-opts"] = {
                "method": self.stream.tcp.request.method,
                "path": self.stream.tcp.request.path,
                "headers": {
                    i["name"]: [i["value"]] for i in self.stream.tcp.request.headers
                },
            }
        if self.stream.network == "grpc":
            data["grpc-opts"] = {
                "grpc-service-name": self.stream.grpc.service_name,
            }
        if self.stream.network == "ws":
            data["ws-opts"] = {
                "path": self.stream.ws.path,
                "headers": XrayCommonClass.to_v2_headers(
                    self.stream.ws.headers, arr=False
                ),
            }
        return data

    def genVLESSClashProfile(self, address, remark):
        """
        返回dict,下面是数据的golang结构体
        Name              string            `proxy:"name"`
        Server            string            `proxy:"server"`
        Port              int               `proxy:"port"`
        UUID              string            `proxy:"uuid"`
        Flow              string            `proxy:"flow,omitempty"`
        FlowShow          bool              `proxy:"flow-show,omitempty"`
        TLS               bool              `proxy:"tls,omitempty"`
        UDP               bool              `proxy:"udp,omitempty"`
        PacketAddr        bool              `proxy:"packet-addr,omitempty"`
        XUDP              bool              `proxy:"xudp,omitempty"`
        PacketEncoding    string            `proxy:"packet-encoding,omitempty"`
        Network           string            `proxy:"network,omitempty"`
        RealityOpts       RealityOptions    `proxy:"reality-opts,omitempty"`
        HTTPOpts          HTTPOptions       `proxy:"http-opts,omitempty"`
        HTTP2Opts         HTTP2Options      `proxy:"h2-opts,omitempty"`
        GrpcOpts          GrpcOptions       `proxy:"grpc-opts,omitempty"`
        WSOpts            WSOptions         `proxy:"ws-opts,omitempty"`
        WSPath            string            `proxy:"ws-path,omitempty"`
        WSHeaders         map[string]string `proxy:"ws-headers,omitempty"`
        SkipCertVerify    bool              `proxy:"skip-cert-verify,omitempty"`
        Fingerprint       string            `proxy:"fingerprint,omitempty"`
        ServerName        string            `proxy:"servername,omitempty"`
        ClientFingerprint string            `proxy:"client-fingerprint,omitempty"`
        """

        data = {
            "name": remark,
            "server": address,
            "port": self.port,
            "uuid": self.settings.vlesses[0].id,
            "flow": self.settings.vlesses[0].flow,
            "tls": self.stream.security != "none",
            "network": self.stream.network,
            "skip-cert-verify": True,
            "servername": self.stream.tls.server,
        }
        if self.stream.network == "http":
            data["http-opts"] = {
                "method": self.stream.tcp.request.method,
                "path": self.stream.tcp.request.path,
                "headers": {
                    i["name"]: [i["value"]] for i in self.stream.tcp.request.headers
                },
            }
        if self.stream.network == "grpc":
            data["grpc-opts"] = {
                "grpc-service-name": self.stream.grpc.service_name,
            }
        if self.stream.network == "ws":
            data["ws-opts"] = {
                "path": self.stream.ws.path,
                "headers": XrayCommonClass.to_v2_headers(
                    self.stream.ws.headers, arr=False
                ),
            }
            data["ws-path"] = self.stream.ws.path
            data["ws-headers"] = XrayCommonClass.to_v2_headers(
                self.stream.ws.headers, arr=False
            )
        return data

    def genSSClashProfile(self, address, remark):
        """
        Name              string         `proxy:"name"`
        Server            string         `proxy:"server"`
        Port              int            `proxy:"port"`
        Password          string         `proxy:"password"`
        Cipher            string         `proxy:"cipher"`
        UDP               bool           `proxy:"udp,omitempty"`
        Plugin            string         `proxy:"plugin,omitempty"`
        PluginOpts        map[string]any `proxy:"plugin-opts,omitempty"`
        UDPOverTCP        bool           `proxy:"udp-over-tcp,omitempty"`
        UDPOverTCPVersion int            `proxy:"udp-over-tcp-version,omitempty"`
        ClientFingerprint string         `proxy:"client-fingerprint,omitempty"`
        """
        return {
            "name": remark,
            "server": address,
            "port": self.port,
            "password": self.settings.password,
            "cipher": self.settings.method,
            "udp": "udp" in self.stream.network,
        }

    def genTrojanClashProfile(self, address, remark):
        """
        Name              string         `proxy:"name"`
        Server            string         `proxy:"server"`
        Port              int            `proxy:"port"`
        Password          string         `proxy:"password"`
        ALPN              []string       `proxy:"alpn,omitempty"`
        SNI               string         `proxy:"sni,omitempty"`
        SkipCertVerify    bool           `proxy:"skip-cert-verify,omitempty"`
        Fingerprint       string         `proxy:"fingerprint,omitempty"`
        UDP               bool           `proxy:"udp,omitempty"`
        Network           string         `proxy:"network,omitempty"`
        RealityOpts       RealityOptions `proxy:"reality-opts,omitempty"`
        GrpcOpts          GrpcOptions    `proxy:"grpc-opts,omitempty"`
        WSOpts            WSOptions      `proxy:"ws-opts,omitempty"`
        Flow              string         `proxy:"flow,omitempty"`
        FlowShow          bool           `proxy:"flow-show,omitempty"`
        ClientFingerprint string         `proxy:"client-fingerprint,omitempty"`
        """
        return {
            "name": remark,
            "type": "trojan",
            "server": address,
            "port": self.port,
            "password": self.settings.clients[0].password,
            "alpn": self.stream.tls.alpn,
            "sni": self.stream.tls.server,
            "skip-cert-verify": True,
            "network": self.stream.network,
            "udp": True,
            "flow": self.flow,
        }

    def genSocksClashProfile(self, address, remark):
        """
        Name           string `proxy:"name"`
        Server         string `proxy:"server"`
        Port           int    `proxy:"port"`
        UserName       string `proxy:"username,omitempty"`
        Password       string `proxy:"password,omitempty"`
        TLS            bool   `proxy:"tls,omitempty"`
        UDP            bool   `proxy:"udp,omitempty"`
        SkipCertVerify bool   `proxy:"skip-cert-verify,omitempty"`
        Fingerprint    string `proxy:"fingerprint,omitempty"`
        """
        return {
            "name": remark,
            "server": address,
            "port": self.port,
            "username": self.username,
            "password": self.password,
            "tls": self.stream.security != "none",
            "udp": self.settings.udp,
            "skip-cert-verify": True,
        }

    def genHttpClashProfile(self, address, remark):
        """
        Name           string            `proxy:"name"`
            Server         string            `proxy:"server"`
            Port           int               `proxy:"port"`
            UserName       string            `proxy:"username,omitempty"`
            Password       string            `proxy:"password,omitempty"`
            TLS            bool              `proxy:"tls,omitempty"`
            SNI            string            `proxy:"sni,omitempty"`
            SkipCertVerify bool              `proxy:"skip-cert-verify,omitempty"`
            Fingerprint    string            `proxy:"fingerprint,omitempty"`
            Headers        map[string]string `proxy:"headers,omitempty"`
        """
        return {
            "name": remark,
            "server": address,
            "port": self.port,
            "username": self.username,
            "password": self.password,
            "tls": self.tls,
            "sni": self.serverName,
            "skip-cert-verify": True,
            "headers": XrayCommonClass.to_v2_headers(
                self.stream.tcp.request.headers, arr=False
            ),
        }

    def genClashProfile(self, address="", remark=""):
        switcher = {
            Protocols.VMESS: self.genVmessClashProfile,
            Protocols.VLESS: self.genVLESSClashProfile,
            Protocols.SHADOWSOCKS: self.genSSClashProfile,
            Protocols.TROJAN: self.genTrojanClashProfile,
            Protocols.SOCKS: self.genSocksClashProfile,
            Protocols.HTTP: self.genHttpClashProfile,
        }
        gen_func = switcher.get(self.protocol, lambda x, y: "")
        data = gen_func(address, remark)
        if not data:
            return None
        protocol = self.protocol
        if protocol == Protocols.SOCKS:
            protocol = "socks5"
        if protocol == Protocols.SHADOWSOCKS:
            protocol = "ss"
            if data["cipher"] == "chacha20-poly1305":
                data["cipher"] = "chacha20-ietf-poly1305"
        data["type"] = protocol
        return data

    @staticmethod
    def from_json(data={}):
        try:
            settingsData = data.get("settings", "{}")
            streamSettingsData = data.get("streamSettings", "{}")
            sniffingData = data.get("sniffing", "{}")
            if not settingsData:
                settingsData = "{}"
            if not streamSettingsData:
                streamSettingsData = "{}"
            if not sniffingData:
                sniffingData = "{}"
            return Inbound(
                data.get("port", RandomUtil.random_int_range(10000, 60000)),
                data.get("listen", ""),
                data.get("protocol", Protocols.VMESS),
                InboundSettings.from_json(
                    data.get("protocol", Protocols.VMESS),
                    json.loads(settingsData),
                ),
                StreamSettings.from_json(json.loads(streamSettingsData)),
                data.get("tag", ""),
                Sniffing.from_json(json.loads(sniffingData)),
            )
        except json.JSONDecodeError:
            # print(data)
            # print("Invalid JSON data")
            pass

    def to_json(self):
        streamSettings = None
        if self.canEnableStream() or self.protocol == Protocols.TROJAN:
            streamSettings = self.stream.to_json()
        return {
            "port": self.port,
            "listen": self.listen,
            "protocol": self.protocol,
            "settings": self.settings.to_json()
            if isinstance(self.settings, XrayCommonClass)
            else self.settings,
            "streamSettings": streamSettings,
            "tag": self.tag,
            "sniffing": self.sniffing.to_json(),
        }


class InboundSettings(XrayCommonClass):
    def __init__(self, protocol):
        super().__init__()
        self.protocol = protocol

    @staticmethod
    def get_settings(protocol):
        switcher = {
            Protocols.VMESS: InboundVmessSettings(protocol),
            Protocols.VLESS: InboundVLESSSettings(protocol),
            Protocols.TROJAN: InboundTrojanSettings(protocol),
            Protocols.SHADOWSOCKS: InboundShadowsocksSettings(protocol),
            Protocols.DOKODEMO: InboundDokodemoSettings(protocol),
            Protocols.MTPROTO: InboundMtprotoSettings(protocol),
            Protocols.SOCKS: InboundSocksSettings(protocol),
            Protocols.HTTP: InboundHttpSettings(protocol),
        }
        return switcher.get(protocol, None)

    @staticmethod
    def from_json(protocol, json):
        switcher = {
            Protocols.VMESS: InboundVmessSettings.from_json,
            Protocols.VLESS: InboundVLESSSettings.from_json,
            Protocols.TROJAN: InboundTrojanSettings.from_json,
            Protocols.SHADOWSOCKS: InboundShadowsocksSettings.from_json,
            Protocols.DOKODEMO: InboundDokodemoSettings.from_json,
            Protocols.MTPROTO: InboundMtprotoSettings.from_json,
            Protocols.SOCKS: InboundSocksSettings.from_json,
            Protocols.HTTP: InboundHttpSettings.from_json,
        }
        return switcher.get(protocol, lambda x: None)(json)

    def to_json(self):
        return {}


class InboundVmessSettings(InboundSettings):
    def __init__(self, protocol, vmesses=None, disable_insecure_encryption=False):
        super().__init__(protocol)
        self.vmesses: typing.Optional[typing.List["InboundVmessSettingsVmess"]] = (
            vmesses if vmesses is not None else [InboundVmessSettingsVmess()]
        )
        self.disable_insecure = disable_insecure_encryption

    def index_of_vmess_by_id(self, vmess_id):
        return next(
            (i for i, vmess in enumerate(self.vmesses) if vmess.id == vmess_id), -1
        )

    def add_vmess(self, vmess):
        if self.index_of_vmess_by_id(vmess.id) < 0:
            self.vmesses.append(vmess)

    def del_vmess(self, vmess):
        i = self.index_of_vmess_by_id(vmess.id)
        if i >= 0:
            self.vmesses.pop(i)

    @staticmethod
    def from_json(json={}):
        return InboundVmessSettings(
            Protocols.VMESS,
            [
                InboundVmessSettingsVmess.from_json(client)
                for client in json.get("clients", [])
            ],
            json.get("disableInsecureEncryption", False),
        )

    def to_json(self):
        return {
            "clients": [vmess.to_json() for vmess in self.vmesses],
            "disableInsecureEncryption": self.disable_insecure,
        }


class InboundVmessSettingsVmess(XrayCommonClass):
    def __init__(self, id=None, alter_id=0):
        super().__init__()
        self.id = id if id is not None else RandomUtil.random_uuid()
        self.alter_id = alter_id

    @staticmethod
    def from_json(json={}):
        return InboundVmessSettingsVmess(
            json.get("id", RandomUtil.random_uuid()), json.get("alterId", 0)
        )

    def to_json(self):
        return {
            "id": self.id,
            "alterId": self.alter_id,
        }


class InboundVLESSSettings(InboundSettings):
    def __init__(self, protocol, vlesses=None, decryption="none", fallbacks=None):
        super().__init__(protocol)
        self.vlesses = vlesses if vlesses is not None else [InboundVLESSSettingsVLESS()]
        self.decryption = decryption
        self.fallbacks = fallbacks if fallbacks is not None else []

    def add_fallback(self, fallback):
        self.fallbacks.append(fallback)

    def del_fallback(self, index):
        del self.fallbacks[index]

    @staticmethod
    def from_json(json={}):
        vlesses = [
            InboundVLESSSettingsVLESS.from_json(client)
            for client in json.get("clients", [])
        ]
        fallbacks = InboundVLESSSettingsFallback.from_json(json.get("fallbacks", []))
        return InboundVLESSSettings(
            Protocols.VLESS, vlesses, json.get("decryption", "none"), fallbacks
        )

    def to_json(self):
        return {
            "clients": [client.to_json() for client in self.vlesses],
            "decryption": self.decryption,
            "fallbacks": [fallback.to_json() for fallback in self.fallbacks],
        }


class InboundVLESSSettingsVLESS(XrayCommonClass):
    def __init__(self, id=None, flow=FLOW_CONTROL.DIRECT):
        super().__init__()
        self.id = id if id is not None else RandomUtil.random_uuid()
        self.flow = flow

    @staticmethod
    def from_json(json={}):
        return InboundVLESSSettingsVLESS(
            json.get("id", RandomUtil.random_uuid()),
            json.get("flow", FLOW_CONTROL.DIRECT),
        )

    def to_json(self):
        return {
            "id": self.id,
            "flow": self.flow,
        }


class InboundVLESSSettingsFallback(XrayCommonClass):
    def __init__(self, name="", alpn="", path="", dest="", xver=0):
        super().__init__()
        self.name = name
        self.alpn = alpn
        self.path = path
        self.dest = dest
        self.xver = xver

    def to_json(self):
        return {
            "name": self.name,
            "alpn": self.alpn,
            "path": self.path,
            "dest": self.dest,
            "xver": self.xver,
        }

    @staticmethod
    def from_json(json=[]):
        return [
            InboundVLESSSettingsFallback(
                fallback.get("name", ""),
                fallback.get("alpn", ""),
                fallback.get("path", ""),
                fallback.get("dest", ""),
                fallback.get("xver", 0),
            )
            for fallback in json
        ]


class InboundTrojanSettings(InboundSettings):
    def __init__(self, protocol, clients=None, fallbacks=None):
        super().__init__(protocol)
        self.clients: typing.List["InboundTrojanSettingsClient"] = (
            clients if clients is not None else [InboundTrojanSettingsClient()]
        )
        self.fallbacks = fallbacks if fallbacks is not None else []

    def add_trojan_fallback(self):
        self.fallbacks.append(InboundTrojanSettingsFallback())

    def del_trojan_fallback(self, index):
        if 0 <= index < len(self.fallbacks):
            self.fallbacks.pop(index)

    def to_json(self):
        return {
            "clients": [client.to_json() for client in self.clients],
            "fallbacks": [fallback.to_json() for fallback in self.fallbacks],
        }

    @staticmethod
    def from_json(json={}):
        clients = [
            InboundTrojanSettingsClient.from_json(c) for c in json.get("clients", [])
        ]
        fallbacks = InboundTrojanSettingsFallback.from_json(json.get("fallbacks", []))
        return InboundTrojanSettings(Protocols.TROJAN, clients, fallbacks)


class InboundTrojanSettingsClient(XrayCommonClass):
    def __init__(self, password=None, flow=FLOW_CONTROL.DIRECT):
        super().__init__()
        self.password = (
            password if password is not None else RandomUtil.random_lower_and_num(10)
        )
        self.flow = flow

    def to_json(self):
        return {"password": self.password, "flow": self.flow}

    @staticmethod
    def from_json(json={}):
        return InboundTrojanSettingsClient(
            json.get("password", RandomUtil.random_lower_and_num(10)),
            json.get("flow", FLOW_CONTROL.DIRECT),
        )


class InboundTrojanSettingsFallback(XrayCommonClass):
    def __init__(self, name="", alpn="", path="", dest="", xver=0):
        super().__init__()
        self.name = name
        self.alpn = alpn
        self.path = path
        self.dest = dest
        self.xver = xver

    def to_json(self):
        xver = int(self.xver) if isinstance(self.xver, (int, float)) else 0
        return {
            "name": self.name,
            "alpn": self.alpn,
            "path": self.path,
            "dest": self.dest,
            "xver": xver,
        }

    @staticmethod
    def from_json(json={}):
        fallbacks = []
        for fallback in json:
            fallbacks.append(
                InboundTrojanSettingsFallback(
                    fallback.get("name", ""),
                    fallback.get("alpn", ""),
                    fallback.get("path", ""),
                    fallback.get("dest", ""),
                    fallback.get("xver", 0),
                )
            )
        return fallbacks


class InboundShadowsocksSettings(InboundSettings):
    def __init__(
        self, protocol, method=SSMethods.AES_256_GCM, password=None, network="tcp,udp"
    ):
        super().__init__(protocol)
        self.method = method
        self.password = (
            password if password is not None else RandomUtil.random_lower_and_num(10)
        )
        self.network = network

    @staticmethod
    def from_json(json={}):
        return InboundShadowsocksSettings(
            Protocols.SHADOWSOCKS,
            json.get("method", SSMethods.AES_256_GCM),
            json.get("password", RandomUtil.random_lower_and_num(10)),
            json.get("network", "tcp,udp"),
        )

    def to_json(self):
        return {
            "method": self.method,
            "password": self.password,
            "network": self.network,
        }


class InboundDokodemoSettings(InboundSettings):
    def __init__(self, protocol, address="", port=0, network="tcp,udp"):
        super().__init__(protocol)
        self.address = address
        self.port = port
        self.network = network

    @staticmethod
    def from_json(json={}):
        return InboundDokodemoSettings(
            Protocols.DOKODEMO,
            json.get("address", ""),
            json.get("port", 0),
            json.get("network", "tcp,udp"),
        )

    def to_json(self):
        return {"address": self.address, "port": self.port, "network": self.network}


class InboundMtprotoSettings(InboundSettings):
    def __init__(self, protocol, users=None):
        super().__init__(protocol)
        self.users = users if users is not None else [InboundMtprotoSettingsMtUser()]

    @staticmethod
    def from_json(json={}):
        users = [
            InboundMtprotoSettings.MtUser.from_json(user)
            for user in json.get("users", [])
        ]
        return InboundMtprotoSettings(Protocols.MTPROTO, users)

    def to_json(self):
        return {"users": [user.to_json() for user in self.users]}


class InboundMtprotoSettingsMtUser(XrayCommonClass):
    def __init__(self, secret=None):
        super().__init__()
        self.secret = secret if secret is not None else RandomUtil.random_mt_secret()

    @staticmethod
    def from_json(json={}):
        return InboundMtprotoSettingsMtUser(
            json.get("secret", RandomUtil.random_mt_secret())
        )

    def to_json(self):
        return {"secret": self.secret}


class InboundSocksSettings(InboundSettings):
    def __init__(
        self, protocol, auth="password", accounts=None, udp=False, ip="127.0.0.1"
    ):
        super().__init__(protocol)
        self.auth = auth
        self.accounts = (
            accounts if accounts is not None else [InboundSocksSettingsSocksAccount()]
        )
        self.udp = udp
        self.ip = ip

    def add_account(self, account):
        self.accounts.append(account)

    def del_account(self, index):
        self.accounts.pop(index)

    @staticmethod
    def from_json(json={}):
        accounts = []
        if json.get("auth") == "password":
            accounts = [
                InboundSocksSettingsSocksAccount.from_json(account)
                for account in json.get("accounts", [])
            ]

        return InboundSocksSettings(
            Protocols.SOCKS,
            json.get("auth", "password"),
            accounts,
            json.get("udp", False),
            json.get("ip", "127.0.0.1"),
        )

    def to_json(self):
        return {
            "auth": self.auth,
            "accounts": [account.to_json() for account in self.accounts]
            if self.auth == "password"
            else None,
            "udp": self.udp,
            "ip": self.ip,
        }


class InboundSocksSettingsSocksAccount(XrayCommonClass):
    def __init__(self, user=None, password=None):
        super().__init__()
        self.user = user if user is not None else RandomUtil.random_lower_and_num(10)
        self.password = (
            password if password is not None else RandomUtil.random_lower_and_num(10)
        )

    @staticmethod
    def from_json(json={}):
        return InboundSocksSettingsSocksAccount(
            json.get("user", RandomUtil.random_lower_and_num(10)),
            json.get("pass", RandomUtil.random_lower_and_num(10)),
        )

    def to_json(self):
        return {"user": self.user, "pass": self.password}


class InboundHttpSettings(InboundSettings):
    def __init__(self, protocol, accounts=None):
        super().__init__(protocol)
        self.accounts = (
            accounts if accounts is not None else [InboundHttpSettingsHttpAccount()]
        )

    def add_account(self, account):
        self.accounts.append(account)

    def del_account(self, index):
        self.accounts.pop(index)

    @staticmethod
    def from_json(json={}):
        accounts = [
            InboundHttpSettingsHttpAccount.from_json(account)
            for account in json.get("accounts", [])
        ]
        return InboundHttpSettings(Protocols.HTTP, accounts)

    def to_json(self):
        return {"accounts": [account.to_json() for account in self.accounts]}


class InboundHttpSettingsHttpAccount(XrayCommonClass):
    def __init__(self, user=None, password=None):
        super().__init__()
        self.user = user if user is not None else RandomUtil.random_lower_and_num(10)
        self.password = (
            password if password is not None else RandomUtil.random_lower_and_num(10)
        )

    @staticmethod
    def from_json(json={}):
        return InboundHttpSettingsHttpAccount(
            json.get("user", RandomUtil.random_lower_and_num(10)),
            json.get("pass", RandomUtil.random_lower_and_num(10)),
        )

    def to_json(self):
        return {"user": self.user, "pass": self.password}
