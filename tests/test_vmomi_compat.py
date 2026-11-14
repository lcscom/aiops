"""vCenter 9.x EventEx.objectType="ContentLibrary"(SOAP 스키마 밖 형식) 이 있어도 이벤트 페이지 해석이 실패하지 않아야 함."""
import io
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

XML = b'''<?xml version="1.0" encoding="UTF-8"?><soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><soapenv:Body><ReadPreviousEventsResponse xmlns="urn:vim25"><returnval xsi:type="EventEx"><key>101</key><chainId>101</chainId><createdTime>2026-10-12T06:00:00Z</createdTime><userName>VSPHERE.LOCAL\\admin</userName><fullFormattedMessage>Library created</fullFormattedMessage><eventTypeId>com.vmware.cl.CreateLibraryEvent</eventTypeId><severity>info</severity><objectId>lib-1</objectId><objectType>ContentLibrary</objectType><objectName>lib01</objectName></returnval><returnval xsi:type="VmPoweredOnEvent"><key>102</key><chainId>102</chainId><createdTime>2026-10-12T06:00:01Z</createdTime><userName>x</userName><fullFormattedMessage>vm on</fullFormattedMessage><template>false</template></returnval></ReadPreviousEventsResponse></soapenv:Body></soapenv:Envelope>'''


def test_unknown_type_name_in_event():
    from pyVmomi import SoapAdapter, VmomiSupport
    from app.connectors import vcenter  # noqa: F401  — 가져오면 보정이 설치됨
    from app.connectors.vcenter import VCenterConnector
    d = SoapAdapter.SoapResponseDeserializer(None)
    evs = d.Deserialize(io.BytesIO(XML), VmomiSupport.GetVmodlType("vim.event.Event[]"))
    assert [e.key for e in evs] == [101, 102]
    assert evs[0].objectType.__name__.endswith("ContentLibrary")
    assert VCenterConnector._ent_name(evs[0])[0] == "lib01"


def test_unknown_xsi_type_still_errors():
    """데이터 개체 형식(xsi:type)은 보정하지 않음 — 엉뚱한 형식으로 조용히 바뀌지 않도록"""
    import pytest
    from pyVmomi import SoapAdapter, VmomiSupport
    bad = XML.replace(b'xsi:type="VmPoweredOnEvent"', b'xsi:type="NoSuchEventXyz"')
    d = SoapAdapter.SoapResponseDeserializer(None)
    with pytest.raises(Exception):
        d.Deserialize(io.BytesIO(bad), VmomiSupport.GetVmodlType("vim.event.Event[]"))


XML_ENTITY = b'''<?xml version="1.0" encoding="UTF-8"?><soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><soapenv:Body><ReadPreviousEventsResponse xmlns="urn:vim25"><returnval xsi:type="AlarmStatusChangedEvent"><key>201</key><chainId>201</chainId><createdTime>2026-10-12T06:10:00Z</createdTime><userName></userName><fullFormattedMessage>Alarm on lib01 changed from Gray to Yellow</fullFormattedMessage><alarm><name>Content Library sync</name><alarm type="Alarm">alarm-9</alarm></alarm><source><name>Datacenters</name><entity type="Folder">group-d1</entity></source><entity><name>lib01</name><entity type="ContentLibrary">lib-1</entity></entity><from>gray</from><to>yellow</to></returnval><returnval xsi:type="VmPoweredOnEvent"><key>202</key><chainId>202</chainId><createdTime>2026-10-12T06:10:01Z</createdTime><userName>x</userName><fullFormattedMessage>vm on</fullFormattedMessage><template>false</template></returnval></ReadPreviousEventsResponse></soapenv:Body></soapenv:Envelope>'''


def test_content_library_as_event_entity_vcenter_911():
    """vCenter 9.1.1: ManagedEntityEventArgument.entity 에 ContentLibrary 참조 — 'expected vim.ManagedEntity' 로 묶음이 버려지지 않아야 함"""
    from pyVmomi import SoapAdapter, VmomiSupport
    from app.connectors import vcenter  # noqa: F401
    d = SoapAdapter.SoapResponseDeserializer(None)
    evs = d.Deserialize(io.BytesIO(XML_ENTITY), VmomiSupport.GetVmodlType("vim.event.Event[]"))
    assert [e.key for e in evs] == [201, 202]
    assert evs[0].entity.name == "lib01" and evs[0].entity.entity._moId == "lib-1"


def test_content_library_moref_first_in_fresh_process():
    """새 프로세스에서 ContentLibrary 가 형식 이름 값보다 '참조 type 속성'으로 먼저 와도(스텁이 아직 없을 때) 해석돼야 함"""
    import subprocess
    root = Path(__file__).resolve().parents[1]
    code = ("import sys, io; sys.path.insert(0, %r)\n"
            "from app.connectors import vmomi_compat as v; v.install()\n"
            "from pyVmomi import SoapAdapter, VmomiSupport\n"
            "import tests.test_vmomi_compat as t\n"
            "evs = SoapAdapter.SoapResponseDeserializer(None).Deserialize(io.BytesIO(t.XML_ENTITY), VmomiSupport.GetVmodlType('vim.event.Event[]'))\n"
            "assert [e.key for e in evs] == [201, 202], evs\n"
            "assert issubclass(type(evs[0].entity.entity), VmomiSupport.GetVmodlType('vim.ManagedEntity'))\n"
            "print('ok', sorted(v.STUBS))\n") % str(root)
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, cwd=root, timeout=60)
    assert r.returncode == 0 and "ok ['ContentLibrary']" in r.stdout, r.stderr[-800:]
