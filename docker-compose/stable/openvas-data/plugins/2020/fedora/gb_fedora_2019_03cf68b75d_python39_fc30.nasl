# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.877096");
  script_version("2020-01-13T11:49:13+0000");
  # TODO: No CVE assigned yet.
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-01-13 11:49:13 +0000 (Mon, 13 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-08 11:19:12 +0000 (Wed, 08 Jan 2020)");
  script_name("Fedora Update for python39 FEDORA-2019-03cf68b75d");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC30");

  script_xref(name:"FEDORA", value:"2019-03cf68b75d");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/WZWIULCL2HDP2PDVZPXCFQZIMVLHXORL");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python39'
  package(s) announced via the FEDORA-2019-03cf68b75d advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Python 3.9 package for developers.

This package exists to allow developers to test their code against a newer
version of Python. This is not a full Python stack and if you wish to run
your applications with Python 3.9, update your Fedora to a newer
version once Python 3.9 is stable.");

  script_tag(name:"affected", value:"'python39' package(s) on Fedora 30.");

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

  if(!isnull(res = isrpmvuln(pkg:"python39", rpm:"python39~3.9.0~a2~1.fc30", rls:"FC30"))) {
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