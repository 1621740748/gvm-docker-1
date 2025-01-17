# OpenVAS Vulnerability Test
# Auto-generated from advisory DSA 2796-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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
  script_oid("1.3.6.1.4.1.25623.1.0.702796");
  script_version("2020-10-05T06:02:24+0000");
  script_cve_id("CVE-2013-4495");
  script_name("Debian Security Advisory DSA 2796-1 (torque - arbitrary code execution)");
  script_tag(name:"last_modification", value:"2020-10-05 06:02:24 +0000 (Mon, 05 Oct 2020)");
  script_tag(name:"creation_date", value:"2013-11-13 00:00:00 +0100 (Wed, 13 Nov 2013)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_xref(name:"URL", value:"http://www.debian.org/security/2013/dsa-2796.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(6|7)");
  script_tag(name:"affected", value:"torque on Debian Linux");
  script_tag(name:"solution", value:"For the oldstable distribution (squeeze), this problem has been fixed in
version 2.4.8+dfsg-9squeeze3.

For the stable distribution (wheezy), this problem has been fixed in
version 2.4.16+dfsg-1+deb7u2.

For the unstable distribution (sid), this problem has been fixed in
version 2.4.16+dfsg-1.3.

We recommend that you upgrade your torque packages.");
  script_tag(name:"summary", value:"Matt Ezell from Oak Ridge National Labs reported a vulnerability in
torque, a PBS-derived batch processing queueing system.

A user could submit executable shell commands on the tail of what is
passed with the -M switch for qsub. This was later passed to a pipe,
making it possible for these commands to be executed as root on the
pbs_server.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libtorque2", ver:"2.4.8+dfsg-9squeeze3", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libtorque2-dev", ver:"2.4.8+dfsg-9squeeze3", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"torque-client", ver:"2.4.8+dfsg-9squeeze3", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"torque-client-x11", ver:"2.4.8+dfsg-9squeeze3", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"torque-common", ver:"2.4.8+dfsg-9squeeze3", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"torque-mom", ver:"2.4.8+dfsg-9squeeze3", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"torque-pam", ver:"2.4.8+dfsg-9squeeze3", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"torque-scheduler", ver:"2.4.8+dfsg-9squeeze3", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"torque-server", ver:"2.4.8+dfsg-9squeeze3", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libtorque2", ver:"2.4.16+dfsg-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libtorque2-dev", ver:"2.4.16+dfsg-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"torque-client", ver:"2.4.16+dfsg-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"torque-client-x11", ver:"2.4.16+dfsg-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"torque-common", ver:"2.4.16+dfsg-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"torque-mom", ver:"2.4.16+dfsg-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"torque-pam", ver:"2.4.16+dfsg-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"torque-scheduler", ver:"2.4.16+dfsg-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"torque-server", ver:"2.4.16+dfsg-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
