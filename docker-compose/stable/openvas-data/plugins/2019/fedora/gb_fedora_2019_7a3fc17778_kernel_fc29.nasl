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
  script_oid("1.3.6.1.4.1.25623.1.0.876995");
  script_version("2020-02-03T08:05:42+0000");
  script_cve_id("CVE-2019-11135", "CVE-2018-12207", "CVE-2019-0154", "CVE-2019-0155", "CVE-2019-17666", "CVE-2019-17052", "CVE-2019-17053", "CVE-2019-17054", "CVE-2019-17055", "CVE-2019-17056", "CVE-2019-14821", "CVE-2019-15504", "CVE-2019-15505", "CVE-2019-15538", "CVE-2019-14814", "CVE-2019-14815", "CVE-2019-14816", "CVE-2019-13631", "CVE-2019-12817", "CVE-2019-11477", "CVE-2019-11479", "CVE-2019-11478", "CVE-2019-10126", "CVE-2019-12614", "CVE-2019-12456", "CVE-2019-12455", "CVE-2019-12454", "CVE-2019-12378", "CVE-2019-3846", "CVE-2019-12380", "CVE-2019-12381", "CVE-2019-12382", "CVE-2019-12379", "CVE-2019-11833", "CVE-2018-12126", "CVE-2018-12127", "CVE-2018-12130", "CVE-2019-11091", "CVE-2019-11884", "CVE-2019-3900", "CVE-2019-9503", "CVE-2019-9500", "CVE-2019-3882", "CVE-2019-9857", "CVE-2019-8980", "CVE-2019-8912", "CVE-2019-7221", "CVE-2019-6974", "CVE-2019-7222", "CVE-2018-16880", "CVE-2019-3459", "CVE-2019-3460", "CVE-2019-3701", "CVE-2018-19824", "CVE-2018-16862", "CVE-2018-19407", "CVE-2019-0117");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-02-03 08:05:42 +0000 (Mon, 03 Feb 2020)");
  script_tag(name:"creation_date", value:"2019-11-14 03:29:25 +0000 (Thu, 14 Nov 2019)");
  script_name("Fedora Update for kernel FEDORA-2019-7a3fc17778");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC29");

  script_xref(name:"FEDORA", value:"2019-7a3fc17778");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/FTRJEQBHRQDOXJQRWADYWVUPJL4B4CG7");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the FEDORA-2019-7a3fc17778 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The kernel meta package");

  script_tag(name:"affected", value:"'kernel' package(s) on Fedora 29.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~5.3.11~100.fc29", rls:"FC29"))) {
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