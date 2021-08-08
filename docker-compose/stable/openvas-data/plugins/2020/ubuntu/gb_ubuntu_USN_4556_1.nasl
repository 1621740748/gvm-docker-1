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
  script_oid("1.3.6.1.4.1.25623.1.0.844628");
  script_version("2020-10-01T09:58:23+0000");
  script_cve_id("CVE-2005-1513", "CVE-2005-1514", "CVE-2005-1515", "CVE-2020-3811", "CVE-2020-3812");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2020-10-01 09:58:23 +0000 (Thu, 01 Oct 2020)");
  script_tag(name:"creation_date", value:"2020-09-30 03:04:19 +0000 (Wed, 30 Sep 2020)");
  script_name("Ubuntu: Security Advisory for netqmail (USN-4556-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU20\.04 LTS");

  script_xref(name:"USN", value:"4556-1");
  script_xref(name:"URL", value:"https://lists.ubuntu.com/archives/ubuntu-security-announce/2020-September/005666.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'netqmail'
  package(s) announced via the USN-4556-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that netqmail did not properly handle certain input. Both
remote and local attackers could use this vulnerability to cause netqmail
to crash or execute arbitrary code. (CVE-2005-1513, CVE-2005-1514,
CVE-2005-1515)

It was discovered that netqmail did not properly handle certain input when
validating email addresses. An attacker could use this to bypass email
address validation. (CVE-2020-3811)

It was discovered that netqmail did not properly handle certain input when
validating email addresses. An attacker could use this vulnerability to
cause netqmail to disclose sensitive information. (CVE-2020-3812)");

  script_tag(name:"affected", value:"'netqmail' package(s) on Ubuntu 20.04 LTS.");

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

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"qmail", ver:"1.06-6.2~deb10u1build0.20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qmail-uids-gids", ver:"1.06-6.2~deb10u1build0.20.04.1", rls:"UBUNTU20.04 LTS"))) {
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