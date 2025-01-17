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
  script_oid("1.3.6.1.4.1.25623.1.0.876992");
  script_version("2019-11-13T08:06:35+0000");
  script_cve_id("CVE-2019-2911", "CVE-2019-2914", "CVE-2019-2938", "CVE-2019-2946", "CVE-2019-2957", "CVE-2019-2960", "CVE-2019-2963", "CVE-2019-2966", "CVE-2019-2967", "CVE-2019-2968", "CVE-2019-2974", "CVE-2019-2982", "CVE-2019-2991", "CVE-2019-2993", "CVE-2019-2997", "CVE-2019-2998", "CVE-2019-3004", "CVE-2019-3009", "CVE-2019-3011", "CVE-2019-3018", "CVE-2019-2420", "CVE-2019-2434", "CVE-2019-2436", "CVE-2019-2455", "CVE-2019-2481", "CVE-2019-2482", "CVE-2019-2486", "CVE-2019-2494", "CVE-2019-2495", "CVE-2019-2502", "CVE-2019-2503", "CVE-2019-2507", "CVE-2019-2510", "CVE-2019-2528", "CVE-2019-2529", "CVE-2019-2530", "CVE-2019-2531", "CVE-2019-2532", "CVE-2019-2533", "CVE-2019-2534", "CVE-2019-2535", "CVE-2019-2536", "CVE-2019-2537", "CVE-2019-2539", "CVE-2018-3276", "CVE-2018-3200", "CVE-2018-3137", "CVE-2018-3284", "CVE-2018-3195", "CVE-2018-3173", "CVE-2018-3212", "CVE-2018-3279", "CVE-2018-3162", "CVE-2018-3247", "CVE-2018-3156", "CVE-2018-3161", "CVE-2018-3278", "CVE-2018-3174", "CVE-2018-3282", "CVE-2018-3285", "CVE-2018-3187", "CVE-2018-3277", "CVE-2018-3144", "CVE-2018-3145", "CVE-2018-3170", "CVE-2018-3186", "CVE-2018-3182", "CVE-2018-3133", "CVE-2018-3143", "CVE-2018-3283", "CVE-2018-3171", "CVE-2018-3251", "CVE-2018-3286", "CVE-2018-3185", "CVE-2018-3280", "CVE-2018-3203", "CVE-2018-3155");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-11-13 08:06:35 +0000 (Wed, 13 Nov 2019)");
  script_tag(name:"creation_date", value:"2019-11-12 03:26:12 +0000 (Tue, 12 Nov 2019)");
  script_name("Fedora Update for community-mysql FEDORA-2019-c1fab3f139");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC29");

  script_xref(name:"FEDORA", value:"2019-c1fab3f139");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/7X5D3O4TOQ57KL5FLQEXH2JB2UQYHCUZ");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'community-mysql'
  package(s) announced via the FEDORA-2019-c1fab3f139 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"MySQL is a multi-user, multi-threaded SQL database server. MySQL is a
client/server implementation consisting of a server daemon (mysqld)
and many different client programs and libraries. The base package
contains the standard MySQL client programs and generic MySQL files.");

  script_tag(name:"affected", value:"'community-mysql' package(s) on Fedora 29.");

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

  if(!isnull(res = isrpmvuln(pkg:"community-mysql", rpm:"community-mysql~8.0.18~1.fc29", rls:"FC29"))) {
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