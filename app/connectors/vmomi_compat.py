"""pyVmomi 호환 보정 — vCenter 가 SOAP 스키마에 없는 관리 개체 형식 이름을 돌려줄 때 수집 전체가 멈추지 않게.

증상: vCenter 9.x 의 콘텐츠 라이브러리 등 일부 이벤트는 EventEx.objectType(vmodl.TypeName)에 "ContentLibrary" 처럼
SOAP(vim25) WSDL 에 없는 형식 이름을 넣는다. pyVmomi 는 이 값을 형식 객체로 바꾸려다 TypeError("ContentLibrary") 를 내고,
그 이벤트가 든 페이지(ReadPreviousEvents) 전체가 실패해 vCenter 이벤트·알람 수집이 멈춘다(pyVmomi 9.1.1 에서도 동일).

보정: '형식 이름 값'을 해석할 때(역직렬화의 EndElementHandler)만, 모르는 이름이면 같은 이름의 빈 관리 개체 형식
(vim.<이름>)을 한 번 만들어 돌려준다. 요소의 xsi:type(데이터 개체 형식) 해석에는 관여하지 않는다.

1.11: vCenter 9.1.1 은 이벤트 인자(EntityEventArgument.entity, 형식 vim.ManagedEntity)에 ContentLibrary 참조를 넣는다.
  스텁의 부모를 vim.ManagedEntity 로 만들고, 관리 개체 참조끼리의 형식 불일치는 CheckField 에서 허용한다
  (TypeError: For "entity" expected type vim.ManagedEntity, but got vim.ContentLibrary → 해당 묶음 건너뜀 문제).
"""
from __future__ import annotations

import re
import sys
import threading

_LOCK = threading.Lock()
_DONE = False
STUBS: set[str] = set()


def install() -> None:
    global _DONE
    if _DONE:
        return
    try:
        from pyVmomi import SoapAdapter, VmomiSupport
    except ImportError:  # pragma: no cover
        return
    orig = SoapAdapter.SoapDeserializer.LookupWsdlType

    def stub(name: str):
        vname = f"vim.{name}"
        with _LOCK:
            try:
                return VmomiSupport.GetVmodlType(vname)
            except (KeyError, AttributeError):
                VmomiSupport.CreateAndLoadManagedType(vname, name, "vim.ManagedEntity", "vim.version.version1", [], [])
                STUBS.add(name)
                return VmomiSupport.GetVmodlType(vname)

    def lookup(self, ns, name, allowManagedObjectReference=False):
        try:
            return orig(self, ns, name, allowManagedObjectReference)
        except KeyError:
            fr = sys._getframe(1)
            caller = fr.f_code.co_name
            # ① 형식 이름 값(EventEx.objectType 등) ② 관리 개체 참조의 type 속성(<entity type="ContentLibrary">) — 둘 다 관리 개체 형식이라 스텁이 안전
            #    (xsi:type 데이터 개체 해석·SOAP fault 형식은 건드리지 않음)
            moref = caller == "StartElementHandler" and not allowManagedObjectReference and "typeAttr" in fr.f_locals
            if (caller == "EndElementHandler" or moref) and re.fullmatch(r"[A-Z][A-Za-z0-9_]{1,80}", name or ""):
                return stub(name)
            raise

    SoapAdapter.SoapDeserializer.LookupWsdlType = lookup

    orig_check = VmomiSupport.CheckField
    MO = VmomiSupport.ManagedObject

    def check(info, val):
        try:
            return orig_check(info, val)
        except TypeError:
            t = getattr(info, "type", None)
            try:                                       # 관리 개체 참조끼리(예: ManagedEntity 자리에 ContentLibrary) → 허용
                if isinstance(val, MO) and isinstance(t, type) and issubclass(t, MO):
                    STUBS.add(type(val).__name__ + "→" + t.__name__)
                    return None
                if isinstance(val, list) and val and all(isinstance(x, MO) for x in val) and hasattr(t, "Item") and issubclass(t.Item, MO):
                    return None
            except TypeError:
                pass
            raise

    VmomiSupport.CheckField = check
    _DONE = True
