# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from the referenced
# advisories, and are Copyright (C) by the respective right holder(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.877688");
  script_version("2020-04-21T09:23:28+0000");
  # TODO: No CVE assigned yet.
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-04-21 09:23:28 +0000 (Tue, 21 Apr 2020)");
  script_tag(name:"creation_date", value:"2020-04-12 03:15:56 +0000 (Sun, 12 Apr 2020)");
  script_name("Fedora: Security Advisory for php-symfony4 (FEDORA-2020-fade6a8df7)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC32");

  script_xref(name:"FEDORA", value:"2020-fade6a8df7");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/C36JLPHUPKDFAX6D5WYFC4ALO2K7RDUQ");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php-symfony4'
  package(s) announced via the FEDORA-2020-fade6a8df7 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Symfony PHP framework (version 4).

NOTE: Does not require PHPUnit bridge.");

  script_tag(name:"affected", value:"'php-symfony4' package(s) on Fedora 32.");

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

if(release == "FC32") {

  if(!isnull(res = isrpmvuln(pkg:"php-symfony4", rpm:"php-symfony4~4.4.7~1.fc32", rls:"FC32"))) {
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