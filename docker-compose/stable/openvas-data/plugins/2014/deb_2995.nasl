# OpenVAS Vulnerability Test
# Auto-generated from advisory DSA 2995-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.702995");
  script_version("2020-02-18T15:18:54+0000");
  script_cve_id("CVE-2014-4607");
  script_name("Debian Security Advisory DSA 2995-1 (lzo2 - security update)");
  script_tag(name:"last_modification", value:"2020-02-18 15:18:54 +0000 (Tue, 18 Feb 2020)");
  script_tag(name:"creation_date", value:"2014-08-03 00:00:00 +0200 (Sun, 03 Aug 2014)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_xref(name:"URL", value:"http://www.debian.org/security/2014/dsa-2995.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");
  script_tag(name:"affected", value:"lzo2 on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (wheezy), this problem has been fixed in
version 2.06-1+deb7u1.

For the testing distribution (jessie), this problem has been fixed in
version 2.08-1.

For the unstable distribution (sid), this problem has been fixed in
version 2.08-1.

We recommend that you upgrade your lzo2 packages.");
  script_tag(name:"summary", value:"Don A. Bailey from Lab Mouse Security discovered an integer overflow
flaw in the way the lzo library decompressed certain archives compressed
with the LZO algorithm. An attacker could create a specially crafted
LZO-compressed input that, when decompressed by an application using the
lzo library, would cause that application to crash or, potentially,
execute arbitrary code.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"liblzo2-2", ver:"2.06-1+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"liblzo2-dev", ver:"2.06-1+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}