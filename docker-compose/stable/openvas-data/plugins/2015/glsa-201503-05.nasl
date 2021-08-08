###############################################################################
# OpenVAS Vulnerability Test
#
# Gentoo Linux security check
#
# Authors:
# Eero Volotinen <eero.volotinen@solinor.com>
#
# Copyright:
# Copyright (C) 2015 Eero Volotinen, http://solinor.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.121359");
  script_version("2020-08-04T08:27:56+0000");
  script_tag(name:"creation_date", value:"2015-09-29 11:28:38 +0300 (Tue, 29 Sep 2015)");
  script_tag(name:"last_modification", value:"2020-08-04 08:27:56 +0000 (Tue, 04 Aug 2020)");
  script_name("Gentoo Security Advisory GLSA 201503-05");
  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in FreeType. Please review the CVE identifiers referenced below for details.");
  script_tag(name:"solution", value:"Update the affected packages to the latest available version.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://security.gentoo.org/glsa/201503-05");
  script_cve_id("CVE-2014-9656", "CVE-2014-9657", "CVE-2014-9658", "CVE-2014-9659", "CVE-2014-9660", "CVE-2014-9661", "CVE-2014-9662", "CVE-2014-9663", "CVE-2014-9664", "CVE-2014-9665", "CVE-2014-9666", "CVE-2014-9667", "CVE-2014-9668", "CVE-2014-9669", "CVE-2014-9670", "CVE-2014-9671", "CVE-2014-9672", "CVE-2014-9673", "CVE-2014-9674", "CVE-2014-9675");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"summary", value:"Gentoo Linux Local Security Checks GLSA 201503-05");
  script_copyright("Copyright (C) 2015 Eero Volotinen");
  script_family("Gentoo Local Security Checks");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-gentoo.inc");

res = "";
report = "";

if((res=ispkgvuln(pkg:"media-libs/freetype", unaffected: make_list("ge 2.5.5"), vulnerable: make_list("lt 2.5.5"))) != NULL) {
  report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
