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
  script_oid("1.3.6.1.4.1.25623.1.0.879885");
  script_version("2021-08-03T06:52:21+0000");
  # TODO: No CVE assigned yet.
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-08-03 06:52:21 +0000 (Tue, 03 Aug 2021)");
  script_tag(name:"creation_date", value:"2021-07-30 03:08:06 +0000 (Fri, 30 Jul 2021)");
  script_name("Fedora: Security Advisory for seamonkey (FEDORA-2021-6a0249cb06)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC34");

  script_xref(name:"Advisory-ID", value:"FEDORA-2021-6a0249cb06");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/FDWOUW5YUUIIAYBKROJ2A6JKQIRQBP5I");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'seamonkey'
  package(s) announced via the FEDORA-2021-6a0249cb06 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"SeaMonkey is an all-in-one Internet application suite (previously made
popular by Netscape and Mozilla). It includes an Internet browser,
advanced e-mail, newsgroup and feed client, a calendar, IRC client,
HTML editor and a tool to inspect the DOM for web pages. It is derived
from the application formerly known as Mozilla Application Suite.");

  script_tag(name:"affected", value:"'seamonkey' package(s) on Fedora 34.");

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

if(release == "FC34") {

  if(!isnull(res = isrpmvuln(pkg:"seamonkey", rpm:"seamonkey~2.53.8.1~1.fc34", rls:"FC34"))) {
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