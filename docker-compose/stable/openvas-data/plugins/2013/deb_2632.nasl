# OpenVAS Vulnerability Test
# Auto-generated from advisory DSA 2632-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.702632");
  script_version("2020-10-05T06:02:24+0000");
  script_cve_id("CVE-2013-0871", "CVE-2013-0231");
  script_name("Debian Security Advisory DSA 2632-1 (linux-2.6 - privilege escalation/denial of service)");
  script_tag(name:"last_modification", value:"2020-10-05 06:02:24 +0000 (Mon, 05 Oct 2020)");
  script_tag(name:"creation_date", value:"2013-02-25 00:00:00 +0100 (Mon, 25 Feb 2013)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_xref(name:"URL", value:"http://www.debian.org/security/2013/dsa-2632.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");
  script_tag(name:"affected", value:"linux-2.6 on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (squeeze), this problem has been fixed in version
2.6.32-48squeeze1.

The following matrix lists additional source packages that were rebuilt for
compatibility with or to take advantage of this update:

?Debian 6.0 (squeeze)user-mode-linux2.6.32-1um-4+48squeeze1
We recommend that you upgrade your linux-2.6 and user-mode-linux packages.");
  script_tag(name:"summary", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead
to a denial of service or privilege escalation. The Common Vulnerabilities and
Exposures project identifies the following problems:

CVE-2013-0231
Jan Beulich provided a fix for an issue in the Xen PCI backend drivers.
Users of guests on a system using passed-through PCI devices can create
a denial of service of the host system due to the use of non-ratelimited
kernel log messages.

CVE-2013-0871
Suleiman Souhlal and Salman Qazi of Google, with help from Aaron Durbin
and Michael Davidson of Google, discovered an issue in the
ptrace subsystem. Due to a race condition with PTRACE_SETREGS, local users
can cause kernel stack corruption and execution of arbitrary code.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"firmware-linux-free", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-base", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-doc-2.6.32", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-486", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-4kc-malta", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-5kc-malta", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-686", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-686-bigmem", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-all", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-all-amd64", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-all-armel", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-all-i386", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-all-ia64", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-all-mips", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-all-mipsel", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-all-powerpc", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-all-s390", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-all-sparc", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-amd64", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-common", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-common-openvz", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-common-vserver", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-common-xen", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-iop32x", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-itanium", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-ixp4xx", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-kirkwood", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-mckinley", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-openvz-686", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-openvz-amd64", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-orion5x", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-powerpc", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-powerpc-smp", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-powerpc64", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-r4k-ip22", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-r5k-cobalt", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-r5k-ip32", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-s390x", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-sb1-bcm91250a", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-sb1a-bcm91480b", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-sparc64", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-sparc64-smp", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-versatile", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-vserver-686", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-vserver-686-bigmem", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-vserver-amd64", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-vserver-itanium", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-vserver-mckinley", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-vserver-powerpc", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-vserver-powerpc64", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-vserver-s390x", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-vserver-sparc64", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-xen-686", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-xen-amd64", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-486", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-4kc-malta", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-5kc-malta", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-686", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-686-bigmem", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-686-bigmem-dbg", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-amd64", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-amd64-dbg", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-iop32x", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-itanium", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-ixp4xx", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-kirkwood", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-mckinley", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-openvz-686", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-openvz-686-dbg", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-openvz-amd64", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-openvz-amd64-dbg", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-orion5x", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-powerpc", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-powerpc-smp", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-powerpc64", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-r4k-ip22", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-r5k-cobalt", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-r5k-ip32", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-s390x", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-s390x-tape", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-sb1-bcm91250a", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-sb1a-bcm91480b", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-sparc64", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-sparc64-smp", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-versatile", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-vserver-686", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-vserver-686-bigmem", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-vserver-686-bigmem-dbg", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-vserver-amd64", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-vserver-amd64-dbg", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-vserver-itanium", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-vserver-mckinley", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-vserver-powerpc", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-vserver-powerpc64", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-vserver-s390x", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-vserver-sparc64", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-xen-686", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-xen-686-dbg", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-xen-amd64", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-xen-amd64-dbg", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-libc-dev", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-manual-2.6.32", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-patch-debian-2.6.32", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-source-2.6.32", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-support-2.6.32-5", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-tools-2.6.32", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xen-linux-system-2.6.32-5-xen-686", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xen-linux-system-2.6.32-5-xen-amd64", ver:"2.6.32-48squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
