# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.844323");
  script_version("2021-07-12T02:00:56+0000");
  script_cve_id("CVE-2019-18634");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-07-12 02:00:56 +0000 (Mon, 12 Jul 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-07 17:15:00 +0000 (Fri, 07 Feb 2020)");
  script_tag(name:"creation_date", value:"2020-02-04 04:00:16 +0000 (Tue, 04 Feb 2020)");
  script_name("Ubuntu: Security Advisory for sudo (USN-4263-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=(UBUNTU19\.10|UBUNTU18\.04 LTS|UBUNTU16\.04 LTS)");

  script_xref(name:"USN", value:"4263-1");
  script_xref(name:"URL", value:"https://lists.ubuntu.com/archives/ubuntu-security-announce/2020-February/005308.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sudo'
  package(s) announced via the USN-4263-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Joe Vennix discovered that Sudo incorrectly handled memory operations when
the pwfeedback option is enabled. A local attacker could possibly use this
issue to obtain unintended access to the administrator account.");

  script_tag(name:"affected", value:"'sudo' package(s) on Ubuntu 19.10, Ubuntu 18.04 LTS, Ubuntu 16.04 LTS.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "UBUNTU19.10") {

  if(!isnull(res = isdpkgvuln(pkg:"sudo", ver:"1.8.27-1ubuntu4.1", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sudo-ldap", ver:"1.8.27-1ubuntu4.1", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"sudo", ver:"1.8.21p2-3ubuntu1.2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sudo-ldap", ver:"1.8.21p2-3ubuntu1.2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"sudo", ver:"1.8.16-0ubuntu1.9", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sudo-ldap", ver:"1.8.16-0ubuntu1.9", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);