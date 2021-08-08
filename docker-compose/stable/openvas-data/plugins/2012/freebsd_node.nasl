###############################################################################
# OpenVAS Vulnerability Test
# $Id: freebsd_node.nasl 11768 2018-10-05 14:07:38Z cfischer $
#
# Auto generated from VID a1d0911f-987a-11e1-a2ef-001fd0af1a4c
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
# advisories, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71382");
  script_version("$Revision: 11768 $");
  script_cve_id("CVE-2012-2330");
  script_tag(name:"last_modification", value:"$Date: 2018-10-05 16:07:38 +0200 (Fri, 05 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-05-31 11:53:51 -0400 (Thu, 31 May 2012)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_name("FreeBSD Ports: node, node-devel");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  node

  node-devel");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://blog.nodejs.org/2012/05/07/http-server-security-vulnerability-please-upgrade-to-0-6-17/");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/a1d0911f-987a-11e1-a2ef-001fd0af1a4c.html");

  script_tag(name:"summary", value:"The remote host is missing an update to the system
  as announced in the referenced advisory.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-bsd.inc");

vuln = FALSE;
txt = "";

bver = portver(pkg:"node");
if(!isnull(bver) && revcomp(a:bver, b:"0.6.17")<0) {
  txt += "Package node version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}
bver = portver(pkg:"node-devel");
if(!isnull(bver) && revcomp(a:bver, b:"0.6.17")<0) {
  txt += "Package node-devel version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}