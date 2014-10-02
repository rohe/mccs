#!/usr/bin/env python
import subprocess
import sys

from saml2 import config
from saml2.attribute_converter import ac_factory
from saml2.mdstore import MetadataStore
from saml2 import sigver
from saml2 import saml
processes = []

from saml2 import md
from saml2.extension import mdui
from saml2.extension import idpdisc
from saml2.extension import dri
from saml2.extension import mdattr
from saml2.extension import ui
import xmldsig
import xmlenc

sec_config = config.Config()

ONTS = {
    saml.NAMESPACE: saml,
    mdui.NAMESPACE: mdui,
    mdattr.NAMESPACE: mdattr,
    dri.NAMESPACE: dri,
    ui.NAMESPACE: ui,
    idpdisc.NAMESPACE: idpdisc,
    md.NAMESPACE: md,
    xmldsig.NAMESPACE: xmldsig,
    xmlenc.NAMESPACE: xmlenc
}

ATTRCONV = ac_factory()

sec_config.xmlsec_binary = sigver.get_xmlsec_binary(["/opt/local/bin"])
mds = MetadataStore(ONTS.values(), ATTRCONV, sec_config,
                    disable_ssl_certificate_validation=True)

mds.imp({"mdfile": ["swamid2.md"]})

# Nagios or or Not Nagios output based on command argument
NAGIOS = False
if len(sys.argv) > 1:
    if sys.argv[1].lower() == "nagios":
        NAGIOS = True

for entity_id in mds.identity_providers():
    print "## %s ##" % entity_id
    if NAGIOS:
        p = subprocess.Popen(['./mccs.py', "-N", "-e", entity_id, "conf"],
                             stdout=subprocess.PIPE)
    else:
        p = subprocess.Popen(['./mccs.py', "-e", entity_id, "conf"],
                             stdout=subprocess.PIPE)
    print p.stdout.read()
