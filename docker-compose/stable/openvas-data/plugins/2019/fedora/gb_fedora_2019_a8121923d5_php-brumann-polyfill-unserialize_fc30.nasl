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
  script_oid("1.3.6.1.4.1.25623.1.0.876534");
  script_version("2019-06-27T06:30:18+0000");
  script_cve_id("CVE-2019-11831", "CVE-2019-11830");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-06-27 06:30:18 +0000 (Thu, 27 Jun 2019)");
  script_tag(name:"creation_date", value:"2019-06-27 02:14:04 +0000 (Thu, 27 Jun 2019)");
  script_name("Fedora Update for php-brumann-polyfill-unserialize FEDORA-2019-a8121923d5");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC30");

  script_xref(name:"FEDORA", value:"2019-a8121923d5");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/VYU6FAW54QNQQBBB27CGXK7D4OQXQ2IP");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php-brumann-polyfill-unserialize'
  package(s) announced via the FEDORA-2019-a8121923d5 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Backports unserialize options introduced in PHP 7.0 to older PHP versions. This
was originally designed as a Proof of Concept for Symfony Issue.

You can use this package in projects that rely on PHP versions older than PHP
7.0. In case you are using PHP 7.0+ the original unserialize() will be used
instead.");

  script_tag(name:"affected", value:"'php-brumann-polyfill-unserialize' package(s) on Fedora 30.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "FC30") {

  if(!isnull(res = isrpmvuln(pkg:"php-brumann-polyfill-unserialize", rpm:"php-brumann-polyfill-unserialize~1.0.3~1.fc30", rls:"FC30"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
