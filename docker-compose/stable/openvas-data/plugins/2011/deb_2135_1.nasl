# OpenVAS Vulnerability Test
# Description: Auto-generated from advisory DSA 2135-1 (xpdf)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (C) 2011 E-Soft Inc. http://www.securityspace.com
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# or at your option, GNU General Public License version 3,
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
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.68977");
  script_version("2020-12-29T11:25:32+0000");
  script_tag(name:"last_modification", value:"2020-12-29 11:25:32 +0000 (Tue, 29 Dec 2020)");
  script_tag(name:"creation_date", value:"2011-03-07 16:04:02 +0100 (Mon, 07 Mar 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2010-3702", "CVE-2010-3704");
  script_name("Debian Security Advisory DSA 2135-1 (xpdf)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 E-Soft Inc. http://www.securityspace.com");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB5");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202135-1");
  script_tag(name:"insight", value:"Joel Voss of Leviathan Security Group discovered two vulnerabilities
in xpdf rendering engine, which may lead to the execution of arbitrary
code if a malformed PDF file is opened.

For the stable distribution (lenny), these problems have been fixed in
version 3.02-1.4+lenny3.

For the upcoming stable distribution (squeeze) and the unstable
distribution (sid), these problems don't apply, since xpdf has been
patched to use the Poppler PDF library.");

  script_tag(name:"solution", value:"We recommend that you upgrade your poppler packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to xpdf
announced via advisory DSA 2135-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"xpdf", ver:"3.02-1.4+lenny3", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xpdf-common", ver:"3.02-1.4+lenny3", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xpdf-reader", ver:"3.02-1.4+lenny3", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xpdf-utils", ver:"3.02-1.4+lenny3", rls:"DEB5")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}