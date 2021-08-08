# Copyright (C) 2021 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892695");
  script_version("2021-06-29T03:00:14+0000");
  script_cve_id("CVE-2021-31870", "CVE-2021-31871", "CVE-2021-31872", "CVE-2021-31873");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-06-29 03:00:14 +0000 (Tue, 29 Jun 2021)");
  script_tag(name:"creation_date", value:"2021-06-29 03:00:14 +0000 (Tue, 29 Jun 2021)");
  script_name("Debian LTS: Security Advisory for klibc (DLA-2695-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2021/06/msg00025.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2695-1");
  script_xref(name:"Advisory-ID", value:"DLA-2695-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/989505");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'klibc'
  package(s) announced via the DLA-2695-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in klibc. Depending on
how klibc is used, these could lead to the execution of arbitrary
code, privilege escalation, or denial of service.

Thanks to Microsoft Vulnerability Research for reporting the heap bugs
and going some of the way to identifying the cpio bugs.

CVE-2021-31870

Multiplication in the calloc() function may result in an integer
overflow and a subsequent heap buffer overflow.

CVE-2021-31871

An integer overflow in the cpio command may result in a NULL
pointer dereference.

CVE-2021-31872

Multiple possible integer overflows in the cpio command on 32-bit
systems may result in a buffer overflow or other security impact.

CVE-2021-31873

Additions in malloc() function may result in integer overflow and
subsequent heap buffer overflow.");

  script_tag(name:"affected", value:"'klibc' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
2.0.4-9+deb9u1.

We recommend that you upgrade your klibc packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"klibc-utils", ver:"2.0.4-9+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libklibc", ver:"2.0.4-9+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libklibc-dev", ver:"2.0.4-9+deb9u1", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
