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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.1600.1");
  script_cve_id("CVE-2015-3622", "CVE-2016-4008");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:06 +0000 (Wed, 09 Jun 2021)");
  script_version("2021-07-22T02:21:52+0000");
  script_tag(name:"last_modification", value:"2021-07-22 02:21:52 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:1600-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:1600-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20161600-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libtasn1' package(s) announced via the SUSE-SU-2016:1600-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libtasn1 fixes the following issues:
- Malformed asn1 definitions could have caused a segmentation fault in the
 asn1 definition parser (bsc#961491)
- CVE-2015-3622: Fixed invalid read in octet string decoding (bsc#929414)
- CVE-2016-4008: Fixed infinite loop while parsing DER certificates
 (bsc#982779)");

  script_tag(name:"affected", value:"'libtasn1' package(s) on SUSE Linux Enterprise Software Development Kit 11-SP4, SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Debuginfo 11-SP4.");

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

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"libtasn1", rpm:"libtasn1~1.5~1.34.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtasn1-3", rpm:"libtasn1-3~1.5~1.34.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtasn1-3-32bit", rpm:"libtasn1-3-32bit~1.5~1.34.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtasn1-3-x86", rpm:"libtasn1-3-x86~1.5~1.34.1", rls:"SLES11.0SP4"))) {
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
