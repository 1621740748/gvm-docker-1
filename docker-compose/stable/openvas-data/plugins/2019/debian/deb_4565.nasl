# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.704565");
  script_version("2019-11-25T10:43:42+0000");
  script_cve_id("CVE-2019-11135", "CVE-2019-11139");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-11-25 10:43:42 +0000 (Mon, 25 Nov 2019)");
  script_tag(name:"creation_date", value:"2019-11-14 03:00:20 +0000 (Thu, 14 Nov 2019)");
  script_name("Debian Security Advisory DSA 4565-1 (intel-microcode - security update)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(9|10)");

  script_xref(name:"URL", value:"https://www.debian.org/security/2019/dsa-4565.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4565-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'intel-microcode'
  package(s) announced via the DSA-4565-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update ships updated CPU microcode for some types of Intel CPUs. In
particular it provides mitigations for the TAA (TSX Asynchronous Abort)
vulnerability. For affected CPUs, to fully mitigate the vulnerability it
is also necessary to update the Linux kernel packages as released in DSA
4564-1.");

  script_tag(name:"affected", value:"'intel-microcode' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For the oldstable distribution (stretch), these problems have been fixed
in version 3.20191112.1~deb9u1.

For the stable distribution (buster), these problems have been fixed in
version 3.20191112.1~deb10u1.

We recommend that you upgrade your intel-microcode packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"intel-microcode", ver:"3.20191112.1~deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"intel-microcode", ver:"3.20191112.1~deb10u1", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);