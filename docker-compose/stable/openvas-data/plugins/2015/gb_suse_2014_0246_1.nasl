# Copyright (C) 2015 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.850831");
  script_version("2020-01-31T07:58:03+0000");
  script_tag(name:"last_modification", value:"2020-01-31 07:58:03 +0000 (Fri, 31 Jan 2020)");
  script_tag(name:"creation_date", value:"2015-10-13 18:35:01 +0530 (Tue, 13 Oct 2015)");
  script_cve_id("CVE-2013-5878", "CVE-2013-5884", "CVE-2013-5887", "CVE-2013-5888",
                "CVE-2013-5889", "CVE-2013-5896", "CVE-2013-5898", "CVE-2013-5899",
                "CVE-2013-5907", "CVE-2013-5910", "CVE-2014-0368", "CVE-2014-0373",
                "CVE-2014-0375", "CVE-2014-0376", "CVE-2014-0387", "CVE-2014-0403",
                "CVE-2014-0410", "CVE-2014-0411", "CVE-2014-0415", "CVE-2014-0416",
                "CVE-2014-0417", "CVE-2014-0422", "CVE-2014-0423", "CVE-2014-0424",
                "CVE-2014-0428");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SUSE: Security Advisory for IBM Java (SUSE-SU-2014:0246-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'IBM Java'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update contains the Oracle January 14 2014 CPU for
  java-1_7_0-ibm.

  Security Issue references:

  * CVE-2014-0428

  * CVE-2014-0422

  * CVE-2013-5907

  * CVE-2014-0415

  * CVE-2014-0410

  * CVE-2013-5889

  * CVE-2014-0417

  * CVE-2014-0387

  * CVE-2014-0424

  * CVE-2013-5878

  * CVE-2014-0373

  * CVE-2014-0375

  * CVE-2014-0403
  Description truncated, please see the referenced URL(s) for more information.");

  script_tag(name:"affected", value:"IBM Java on SUSE Linux Enterprise Server 11 SP3");

  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_xref(name:"SUSE-SU", value:"2014:0246-1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=SLES11\.0SP3");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLES11.0SP3") {
  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-ibm", rpm:"java-1_7_0-ibm~1.7.0_sr6.1~0.8.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-ibm-jdbc", rpm:"java-1_7_0-ibm-jdbc~1.7.0_sr6.1~0.8.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-ibm-alsa", rpm:"java-1_7_0-ibm-alsa~1.7.0_sr6.1~0.8.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-ibm-plugin", rpm:"java-1_7_0-ibm-plugin~1.7.0_sr6.1~0.8.1", rls:"SLES11.0SP3"))) {
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
