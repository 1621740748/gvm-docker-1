# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.876855");
  script_version("2020-11-19T14:17:11+0000");
  script_cve_id("CVE-2019-1010228");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-11-19 14:17:11 +0000 (Thu, 19 Nov 2020)");
  script_tag(name:"creation_date", value:"2019-09-27 02:33:43 +0000 (Fri, 27 Sep 2019)");
  script_name("Fedora Update for dcmtk FEDORA-2019-4349fc0afb");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC29");

  script_xref(name:"FEDORA", value:"2019-4349fc0afb");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/NQOAULR72EYJQ4HS6YGLK2S6YNEXY2ET");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dcmtk'
  package(s) announced via the FEDORA-2019-4349fc0afb advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"DCMTK is a collection of libraries and applications implementing large
parts the DICOM standard. It includes software for examining,
constructing and converting DICOM image files, handling offline media,
sending and receiving images over a network connection, as well as
demonstrative image storage and worklist servers. DCMTK is written
in a mixture of ANSI C and C++.  It comes in complete source code and
is made available as 'open source' software. This package includes
multiple fixes taken from the 'patched DCMTK' project.

Install DCMTK if you are working with DICOM format medical image files.");

  script_tag(name:"affected", value:"'dcmtk' package(s) on Fedora 29.");

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

if(release == "FC29") {

  if(!isnull(res = isrpmvuln(pkg:"dcmtk", rpm:"dcmtk~3.6.2~6.fc29", rls:"FC29"))) {
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
