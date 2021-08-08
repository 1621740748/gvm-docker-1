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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.1341.1");
  script_cve_id("CVE-2015-0247", "CVE-2015-1572");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2021-07-22T02:21:52+0000");
  script_tag(name:"last_modification", value:"2021-07-22 02:21:52 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-09 19:55:00 +0000 (Tue, 09 Oct 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:1341-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:1341-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20151341-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'e2fsprogs' package(s) announced via the SUSE-SU-2015:1341-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two security issues were fixed in e2fsprogs:
Security issues fixed:
* CVE-2015-0247: Various heap overflows were fixed in e2fsprogs (fsck,
 dumpe2fs, e2image...).
* CVE-2015-1572: Fixed a potential buffer overflow in closefs()
 (bsc#918346 )");

  script_tag(name:"affected", value:"'e2fsprogs' package(s) on SUSE Linux Enterprise Software Development Kit 12, SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Desktop 12.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"e2fsprogs", rpm:"e2fsprogs~1.42.11~7.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"e2fsprogs-debuginfo", rpm:"e2fsprogs-debuginfo~1.42.11~7.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"e2fsprogs-debugsource", rpm:"e2fsprogs-debugsource~1.42.11~7.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcom_err2", rpm:"libcom_err2~1.42.11~7.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcom_err2-debuginfo", rpm:"libcom_err2-debuginfo~1.42.11~7.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libext2fs2", rpm:"libext2fs2~1.42.11~7.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libext2fs2-debuginfo", rpm:"libext2fs2-debuginfo~1.42.11~7.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"e2fsprogs-debuginfo-32bit", rpm:"e2fsprogs-debuginfo-32bit~1.42.11~7.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcom_err2-32bit", rpm:"libcom_err2-32bit~1.42.11~7.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcom_err2-debuginfo-32bit", rpm:"libcom_err2-debuginfo-32bit~1.42.11~7.1", rls:"SLES12.0"))) {
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