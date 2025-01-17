# OpenVAS Vulnerability Test
# Auto-generated from advisory DSA 3222-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.703222");
  script_version("2019-12-20T08:10:23+0000");
  script_cve_id("CVE-2015-1821", "CVE-2015-1822", "CVE-2015-1853");
  script_name("Debian Security Advisory DSA 3222-1 (chrony - security update)");
  script_tag(name:"last_modification", value:"2019-12-20 08:10:23 +0000 (Fri, 20 Dec 2019)");
  script_tag(name:"creation_date", value:"2015-04-12 00:00:00 +0200 (Sun, 12 Apr 2015)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2015/dsa-3222.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");
  script_tag(name:"affected", value:"chrony on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (wheezy),
these problems have been fixed in version 1.24-3.1+deb7u3.

For the unstable distribution (sid), these problems have been fixed in
version 1.30-2.

We recommend that you upgrade your chrony packages.");
  script_tag(name:"summary", value:"Miroslav Lichvar of Red Hat discovered
multiple vulnerabilities in chrony, an alternative NTP client and server:

CVE-2015-1821
Using particular address/subnet pairs when configuring access control
would cause an invalid memory write. This could allow attackers to
cause a denial of service (crash) or execute arbitrary code.

CVE-2015-1822
When allocating memory to save unacknowledged replies to authenticated
command requests, a pointer would be left uninitialized, which could
trigger an invalid memory write. This could allow attackers to cause a
denial of service (crash) or execute arbitrary code.

CVE-2015-1853
When peering with other NTP hosts using authenticated symmetric
association, the internal state variables would be updated before the
MAC of the NTP messages was validated. This could allow a remote
attacker to cause a denial of service by impeding synchronization
between NTP peers.");
  script_tag(name:"vuldetect", value:"This check tests the installed
software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"chrony", ver:"1.24-3.1+deb7u3", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}