"""Object / attribute & class-state taint fixture (Task 20.3): taint through instance state.

Every view here is routed in ``urls.py`` (Django), so its parameters are tainted sources. The
flows then travel through *object state* — ``self.attr`` written and later read, constructor
parameters stored on fields, a dataclass field, and a non-constructor setter — which earlier
phases (locals/containers/cross-module) could not follow. The dynamic-attribute case proves the
soundness contract: a ``setattr`` whose name we cannot pin escalates to ``DYNAMIC-UNKNOWN``, never
silent clean. The two negative cases (literal-constructed instance, untracked field) must stay
``POSSIBLE-FLOW`` — a real flow is never invented.
"""

import os

from django.views import View

from models import Cmd, Holder, Mutable, Service


class StoreView(View):
    def post(self, request, raw):
        # attr set -> get -> sink, all within one method: self.cmd carries the tainted param.
        self.cmd = raw
        os.system(self.cmd)


def run_view(request, raw):
    # constructor-taint across methods: __init__ stores raw on self.cmd; execute() sinks it.
    svc = Service(raw)
    svc.execute()


def data_view(request, raw):
    # dataclass field: Cmd(raw) maps the tainted arg onto field ``value``; read it into a sink.
    box = Cmd(raw)
    os.system(box.value)


def setter_view(request, raw):
    # non-constructor setter: configure() writes self.data; a later run() reads it into the sink.
    obj = Mutable()
    obj.configure(raw)
    obj.run()


def dynamic_view(request, raw):
    # dynamic attribute write: the field name is computed, so the object is tainted DYNAMICALLY ->
    # the later read is DYNAMIC-UNKNOWN (not ruled out), never CONFIRMED and never dropped.
    holder = Holder()
    setattr(holder, "cmd", raw)
    os.system(holder.cmd)


def literal_view(request, raw):
    # negative: the field is constructed from a literal, so it is never tainted ->
    # the sink stays POSSIBLE-FLOW (baseline), never escalated to CONFIRMED.
    box = Cmd("ls -la")
    os.system(box.value)


def untracked_view(request, raw):
    # negative: a field that is never assigned a tainted value -> read stays clean.
    holder = Holder()
    os.system(holder.cmd)
