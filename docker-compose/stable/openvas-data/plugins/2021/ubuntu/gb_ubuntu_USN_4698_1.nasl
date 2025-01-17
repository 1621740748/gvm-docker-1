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
  script_oid("1.3.6.1.4.1.25623.1.0.844792");
  script_version("2021-02-02T09:53:24+0000");
  script_cve_id("CVE-2020-25681", "CVE-2020-25687", "CVE-2020-25682", "CVE-2020-25683", "CVE-2020-25684", "CVE-2020-25685", "CVE-2020-25686", "CVE-2019-14834");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:C");
  script_tag(name:"last_modification", value:"2021-02-02 09:53:24 +0000 (Tue, 02 Feb 2021)");
  script_tag(name:"creation_date", value:"2021-01-20 04:00:24 +0000 (Wed, 20 Jan 2021)");
  script_name("Ubuntu: Security Advisory for dnsmasq (USN-4698-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=(UBUNTU20\.04 LTS|UBUNTU18\.04 LTS|UBUNTU16\.04 LTS|UBUNTU20\.10)");

  script_xref(name:"USN", value:"4698-1");
  script_xref(name:"URL", value:"https://lists.ubuntu.com/archives/ubuntu-security-announce/2021-January/005845.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dnsmasq'
  package(s) announced via the USN-4698-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Moshe Kol and Shlomi Oberman discovered that Dnsmasq incorrectly handled
memory when sorting RRsets. A remote attacker could use this issue to cause
Dnsmasq to hang, resulting in a denial of service, or possibly execute
arbitrary code. (CVE-2020-25681, CVE-2020-25687)

Moshe Kol and Shlomi Oberman discovered that Dnsmasq incorrectly handled
extracting certain names. A remote attacker could use this issue to cause
Dnsmasq to hang, resulting in a denial of service, or possibly execute
arbitrary code. (CVE-2020-25682, CVE-2020-25683)

Moshe Kol and Shlomi Oberman discovered that Dnsmasq incorrectly
implemented address/port checks. A remote attacker could use this issue to
perform a cache poisoning attack. (CVE-2020-25684)

Moshe Kol and Shlomi Oberman discovered that Dnsmasq incorrectly
implemented query resource name checks. A remote attacker could use this
issue to perform a cache poisoning attack. (CVE-2020-25685)

Moshe Kol and Shlomi Oberman discovered that Dnsmasq incorrectly handled
multiple query requests for the same resource name. A remote attacker could
use this issue to perform a cache poisoning attack. (CVE-2020-25686)

It was discovered that Dnsmasq incorrectly handled memory during DHCP
response creation. A remote attacker could possibly use this issue to
cause Dnsmasq to consume resources, leading to a denial of service. This
issue only affected Ubuntu 16.04 LTS, Ubuntu 18.04 LTS, and Ubuntu 20.04
LTS. (CVE-2019-14834)");

  script_tag(name:"affected", value:"'dnsmasq' package(s) on Ubuntu 20.10, Ubuntu 20.04 LTS, Ubuntu 18.04 LTS, Ubuntu 16.04 LTS.");

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

  if(!isnull(res = isdpkgvuln(pkg:"dnsmasq", ver:"2.80-1.1ubuntu1.2", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dnsmasq-base", ver:"2.80-1.1ubuntu1.2", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dnsmasq-utils", ver:"2.80-1.1ubuntu1.2", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"dnsmasq", ver:"2.79-1ubuntu0.2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dnsmasq-base", ver:"2.79-1ubuntu0.2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dnsmasq-utils", ver:"2.79-1ubuntu0.2", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"dnsmasq", ver:"2.75-1ubuntu0.16.04.7", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dnsmasq-base", ver:"2.75-1ubuntu0.16.04.7", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dnsmasq-utils", ver:"2.75-1ubuntu0.16.04.7", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU20.10") {

  if(!isnull(res = isdpkgvuln(pkg:"dnsmasq", ver:"2.82-1ubuntu1.1", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dnsmasq-base", ver:"2.82-1ubuntu1.1", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dnsmasq-utils", ver:"2.82-1ubuntu1.1", rls:"UBUNTU20.10"))) {
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