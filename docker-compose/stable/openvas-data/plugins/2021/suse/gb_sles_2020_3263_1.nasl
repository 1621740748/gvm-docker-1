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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.3263.1");
  script_cve_id("CVE-2020-13844");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2021-07-22T02:21:52+0000");
  script_tag(name:"last_modification", value:"2021-07-22 02:21:52 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-18 21:15:00 +0000 (Sun, 18 Oct 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:3263-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5|SLES12\.0SP4|SLES12\.0SP3|SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:3263-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20203263-1/");
  script_xref(name:"URL", value:"https://gcc.gnu.org/gcc-10/changes.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gcc10' package(s) announced via the SUSE-SU-2020:3263-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for gcc10 fixes the following issues: This update provides the GCC10 compiler suite and runtime libraries.

The base SUSE Linux Enterprise libraries libgcc_s1, libstdc++6 are replaced by the gcc10 variants.

The new compiler variants are available with '-10' suffix, you can specify them via:

 CC=gcc-10 CXX=g++-10

or similar commands.

For a detailed changelog check out [link moved to references]");

  script_tag(name:"affected", value:"'gcc10' package(s) on SUSE OpenStack Cloud Crowbar 9, SUSE OpenStack Cloud Crowbar 8, SUSE OpenStack Cloud 9, SUSE OpenStack Cloud 8, SUSE OpenStack Cloud 7, SUSE Linux Enterprise Server for SAP 12-SP4, SUSE Linux Enterprise Server for SAP 12-SP3, SUSE Linux Enterprise Server for SAP 12-SP2, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Module for Toolchain 12, SUSE Enterprise Storage 5, HPE Helion Openstack 8.");

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

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"gcc10-debuginfo", rpm:"gcc10-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc10-debugsource", rpm:"gcc10-debugsource~10.2.1+git583~1.3.5", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasan6", rpm:"libasan6~10.2.1+git583~1.3.5", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasan6-debuginfo", rpm:"libasan6-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libatomic1", rpm:"libatomic1~10.2.1+git583~1.3.5", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libatomic1-debuginfo", rpm:"libatomic1-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcc_s1", rpm:"libgcc_s1~10.2.1+git583~1.3.5", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcc_s1-debuginfo", rpm:"libgcc_s1-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgfortran5", rpm:"libgfortran5~10.2.1+git583~1.3.5", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgfortran5-debuginfo", rpm:"libgfortran5-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgo16", rpm:"libgo16~10.2.1+git583~1.3.5", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgo16-debuginfo", rpm:"libgo16-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgomp1", rpm:"libgomp1~10.2.1+git583~1.3.5", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgomp1-debuginfo", rpm:"libgomp1-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libitm1", rpm:"libitm1~10.2.1+git583~1.3.5", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libitm1-debuginfo", rpm:"libitm1-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libobjc4", rpm:"libobjc4~10.2.1+git583~1.3.5", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libobjc4-debuginfo", rpm:"libobjc4-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6", rpm:"libstdc++6~10.2.1+git583~1.3.5", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6-debuginfo", rpm:"libstdc++6-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6-locale", rpm:"libstdc++6-locale~10.2.1+git583~1.3.5", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6-pp-gcc10", rpm:"libstdc++6-pp-gcc10~10.2.1+git583~1.3.5", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libubsan1", rpm:"libubsan1~10.2.1+git583~1.3.5", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libubsan1-debuginfo", rpm:"libubsan1-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblsan0", rpm:"liblsan0~10.2.1+git583~1.3.5", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblsan0-debuginfo", rpm:"liblsan0-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtsan0", rpm:"libtsan0~10.2.1+git583~1.3.5", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtsan0-debuginfo", rpm:"libtsan0-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquadmath0", rpm:"libquadmath0~10.2.1+git583~1.3.5", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquadmath0-debuginfo", rpm:"libquadmath0-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasan6-32bit", rpm:"libasan6-32bit~10.2.1+git583~1.3.5", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasan6-32bit-debuginfo", rpm:"libasan6-32bit-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libatomic1-32bit", rpm:"libatomic1-32bit~10.2.1+git583~1.3.5", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libatomic1-32bit-debuginfo", rpm:"libatomic1-32bit-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcc_s1-32bit", rpm:"libgcc_s1-32bit~10.2.1+git583~1.3.5", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcc_s1-32bit-debuginfo", rpm:"libgcc_s1-32bit-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgfortran5-32bit", rpm:"libgfortran5-32bit~10.2.1+git583~1.3.5", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgfortran5-32bit-debuginfo", rpm:"libgfortran5-32bit-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgo16-32bit", rpm:"libgo16-32bit~10.2.1+git583~1.3.5", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgo16-32bit-debuginfo", rpm:"libgo16-32bit-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgomp1-32bit", rpm:"libgomp1-32bit~10.2.1+git583~1.3.5", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgomp1-32bit-debuginfo", rpm:"libgomp1-32bit-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libitm1-32bit", rpm:"libitm1-32bit~10.2.1+git583~1.3.5", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libitm1-32bit-debuginfo", rpm:"libitm1-32bit-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libobjc4-32bit", rpm:"libobjc4-32bit~10.2.1+git583~1.3.5", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libobjc4-32bit-debuginfo", rpm:"libobjc4-32bit-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6-32bit", rpm:"libstdc++6-32bit~10.2.1+git583~1.3.5", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6-32bit-debuginfo", rpm:"libstdc++6-32bit-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libubsan1-32bit", rpm:"libubsan1-32bit~10.2.1+git583~1.3.5", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libubsan1-32bit-debuginfo", rpm:"libubsan1-32bit-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquadmath0-32bit", rpm:"libquadmath0-32bit~10.2.1+git583~1.3.5", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquadmath0-32bit-debuginfo", rpm:"libquadmath0-32bit-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6-pp-gcc10-32bit", rpm:"libstdc++6-pp-gcc10-32bit~10.2.1+git583~1.3.5", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"gcc10-debuginfo", rpm:"gcc10-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc10-debugsource", rpm:"gcc10-debugsource~10.2.1+git583~1.3.5", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasan6", rpm:"libasan6~10.2.1+git583~1.3.5", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasan6-debuginfo", rpm:"libasan6-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libatomic1", rpm:"libatomic1~10.2.1+git583~1.3.5", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libatomic1-debuginfo", rpm:"libatomic1-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcc_s1", rpm:"libgcc_s1~10.2.1+git583~1.3.5", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcc_s1-debuginfo", rpm:"libgcc_s1-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgfortran5", rpm:"libgfortran5~10.2.1+git583~1.3.5", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgfortran5-debuginfo", rpm:"libgfortran5-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgo16", rpm:"libgo16~10.2.1+git583~1.3.5", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgo16-debuginfo", rpm:"libgo16-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgomp1", rpm:"libgomp1~10.2.1+git583~1.3.5", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgomp1-debuginfo", rpm:"libgomp1-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libitm1", rpm:"libitm1~10.2.1+git583~1.3.5", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libitm1-debuginfo", rpm:"libitm1-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libobjc4", rpm:"libobjc4~10.2.1+git583~1.3.5", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libobjc4-debuginfo", rpm:"libobjc4-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6", rpm:"libstdc++6~10.2.1+git583~1.3.5", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6-debuginfo", rpm:"libstdc++6-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6-locale", rpm:"libstdc++6-locale~10.2.1+git583~1.3.5", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6-pp-gcc10", rpm:"libstdc++6-pp-gcc10~10.2.1+git583~1.3.5", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libubsan1", rpm:"libubsan1~10.2.1+git583~1.3.5", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libubsan1-debuginfo", rpm:"libubsan1-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblsan0", rpm:"liblsan0~10.2.1+git583~1.3.5", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblsan0-debuginfo", rpm:"liblsan0-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtsan0", rpm:"libtsan0~10.2.1+git583~1.3.5", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtsan0-debuginfo", rpm:"libtsan0-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquadmath0", rpm:"libquadmath0~10.2.1+git583~1.3.5", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquadmath0-debuginfo", rpm:"libquadmath0-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasan6-32bit", rpm:"libasan6-32bit~10.2.1+git583~1.3.5", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasan6-32bit-debuginfo", rpm:"libasan6-32bit-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libatomic1-32bit", rpm:"libatomic1-32bit~10.2.1+git583~1.3.5", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libatomic1-32bit-debuginfo", rpm:"libatomic1-32bit-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcc_s1-32bit", rpm:"libgcc_s1-32bit~10.2.1+git583~1.3.5", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcc_s1-32bit-debuginfo", rpm:"libgcc_s1-32bit-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgfortran5-32bit", rpm:"libgfortran5-32bit~10.2.1+git583~1.3.5", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgfortran5-32bit-debuginfo", rpm:"libgfortran5-32bit-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgo16-32bit", rpm:"libgo16-32bit~10.2.1+git583~1.3.5", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgo16-32bit-debuginfo", rpm:"libgo16-32bit-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgomp1-32bit", rpm:"libgomp1-32bit~10.2.1+git583~1.3.5", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgomp1-32bit-debuginfo", rpm:"libgomp1-32bit-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libitm1-32bit", rpm:"libitm1-32bit~10.2.1+git583~1.3.5", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libitm1-32bit-debuginfo", rpm:"libitm1-32bit-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libobjc4-32bit", rpm:"libobjc4-32bit~10.2.1+git583~1.3.5", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libobjc4-32bit-debuginfo", rpm:"libobjc4-32bit-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6-32bit", rpm:"libstdc++6-32bit~10.2.1+git583~1.3.5", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6-32bit-debuginfo", rpm:"libstdc++6-32bit-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6-pp-gcc10-32bit", rpm:"libstdc++6-pp-gcc10-32bit~10.2.1+git583~1.3.5", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libubsan1-32bit", rpm:"libubsan1-32bit~10.2.1+git583~1.3.5", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libubsan1-32bit-debuginfo", rpm:"libubsan1-32bit-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquadmath0-32bit", rpm:"libquadmath0-32bit~10.2.1+git583~1.3.5", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquadmath0-32bit-debuginfo", rpm:"libquadmath0-32bit-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"gcc10-debuginfo", rpm:"gcc10-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc10-debugsource", rpm:"gcc10-debugsource~10.2.1+git583~1.3.5", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasan6", rpm:"libasan6~10.2.1+git583~1.3.5", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasan6-debuginfo", rpm:"libasan6-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libatomic1", rpm:"libatomic1~10.2.1+git583~1.3.5", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libatomic1-debuginfo", rpm:"libatomic1-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcc_s1", rpm:"libgcc_s1~10.2.1+git583~1.3.5", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcc_s1-debuginfo", rpm:"libgcc_s1-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgfortran5", rpm:"libgfortran5~10.2.1+git583~1.3.5", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgfortran5-debuginfo", rpm:"libgfortran5-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgo16", rpm:"libgo16~10.2.1+git583~1.3.5", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgo16-debuginfo", rpm:"libgo16-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgomp1", rpm:"libgomp1~10.2.1+git583~1.3.5", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgomp1-debuginfo", rpm:"libgomp1-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libitm1", rpm:"libitm1~10.2.1+git583~1.3.5", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libitm1-debuginfo", rpm:"libitm1-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libobjc4", rpm:"libobjc4~10.2.1+git583~1.3.5", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libobjc4-debuginfo", rpm:"libobjc4-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6", rpm:"libstdc++6~10.2.1+git583~1.3.5", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6-debuginfo", rpm:"libstdc++6-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6-locale", rpm:"libstdc++6-locale~10.2.1+git583~1.3.5", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6-pp-gcc10", rpm:"libstdc++6-pp-gcc10~10.2.1+git583~1.3.5", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libubsan1", rpm:"libubsan1~10.2.1+git583~1.3.5", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libubsan1-debuginfo", rpm:"libubsan1-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblsan0", rpm:"liblsan0~10.2.1+git583~1.3.5", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblsan0-debuginfo", rpm:"liblsan0-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtsan0", rpm:"libtsan0~10.2.1+git583~1.3.5", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtsan0-debuginfo", rpm:"libtsan0-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquadmath0", rpm:"libquadmath0~10.2.1+git583~1.3.5", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquadmath0-debuginfo", rpm:"libquadmath0-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasan6-32bit", rpm:"libasan6-32bit~10.2.1+git583~1.3.5", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasan6-32bit-debuginfo", rpm:"libasan6-32bit-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libatomic1-32bit", rpm:"libatomic1-32bit~10.2.1+git583~1.3.5", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libatomic1-32bit-debuginfo", rpm:"libatomic1-32bit-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcc_s1-32bit", rpm:"libgcc_s1-32bit~10.2.1+git583~1.3.5", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcc_s1-32bit-debuginfo", rpm:"libgcc_s1-32bit-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgfortran5-32bit", rpm:"libgfortran5-32bit~10.2.1+git583~1.3.5", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgfortran5-32bit-debuginfo", rpm:"libgfortran5-32bit-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgo16-32bit", rpm:"libgo16-32bit~10.2.1+git583~1.3.5", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgo16-32bit-debuginfo", rpm:"libgo16-32bit-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgomp1-32bit", rpm:"libgomp1-32bit~10.2.1+git583~1.3.5", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgomp1-32bit-debuginfo", rpm:"libgomp1-32bit-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libitm1-32bit", rpm:"libitm1-32bit~10.2.1+git583~1.3.5", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libitm1-32bit-debuginfo", rpm:"libitm1-32bit-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libobjc4-32bit", rpm:"libobjc4-32bit~10.2.1+git583~1.3.5", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libobjc4-32bit-debuginfo", rpm:"libobjc4-32bit-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6-32bit", rpm:"libstdc++6-32bit~10.2.1+git583~1.3.5", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6-32bit-debuginfo", rpm:"libstdc++6-32bit-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6-pp-gcc10-32bit", rpm:"libstdc++6-pp-gcc10-32bit~10.2.1+git583~1.3.5", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libubsan1-32bit", rpm:"libubsan1-32bit~10.2.1+git583~1.3.5", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libubsan1-32bit-debuginfo", rpm:"libubsan1-32bit-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquadmath0-32bit", rpm:"libquadmath0-32bit~10.2.1+git583~1.3.5", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquadmath0-32bit-debuginfo", rpm:"libquadmath0-32bit-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"gcc10-debuginfo", rpm:"gcc10-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc10-debugsource", rpm:"gcc10-debugsource~10.2.1+git583~1.3.5", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasan6", rpm:"libasan6~10.2.1+git583~1.3.5", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasan6-debuginfo", rpm:"libasan6-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libatomic1", rpm:"libatomic1~10.2.1+git583~1.3.5", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libatomic1-debuginfo", rpm:"libatomic1-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcc_s1", rpm:"libgcc_s1~10.2.1+git583~1.3.5", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcc_s1-debuginfo", rpm:"libgcc_s1-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgfortran5", rpm:"libgfortran5~10.2.1+git583~1.3.5", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgfortran5-debuginfo", rpm:"libgfortran5-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgo16", rpm:"libgo16~10.2.1+git583~1.3.5", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgo16-debuginfo", rpm:"libgo16-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgomp1", rpm:"libgomp1~10.2.1+git583~1.3.5", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgomp1-debuginfo", rpm:"libgomp1-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libitm1", rpm:"libitm1~10.2.1+git583~1.3.5", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libitm1-debuginfo", rpm:"libitm1-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libobjc4", rpm:"libobjc4~10.2.1+git583~1.3.5", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libobjc4-debuginfo", rpm:"libobjc4-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6", rpm:"libstdc++6~10.2.1+git583~1.3.5", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6-debuginfo", rpm:"libstdc++6-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6-locale", rpm:"libstdc++6-locale~10.2.1+git583~1.3.5", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6-pp-gcc10", rpm:"libstdc++6-pp-gcc10~10.2.1+git583~1.3.5", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libubsan1", rpm:"libubsan1~10.2.1+git583~1.3.5", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libubsan1-debuginfo", rpm:"libubsan1-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblsan0", rpm:"liblsan0~10.2.1+git583~1.3.5", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblsan0-debuginfo", rpm:"liblsan0-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquadmath0", rpm:"libquadmath0~10.2.1+git583~1.3.5", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquadmath0-debuginfo", rpm:"libquadmath0-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtsan0", rpm:"libtsan0~10.2.1+git583~1.3.5", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtsan0-debuginfo", rpm:"libtsan0-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasan6-32bit", rpm:"libasan6-32bit~10.2.1+git583~1.3.5", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasan6-32bit-debuginfo", rpm:"libasan6-32bit-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libatomic1-32bit", rpm:"libatomic1-32bit~10.2.1+git583~1.3.5", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcc_s1-32bit", rpm:"libgcc_s1-32bit~10.2.1+git583~1.3.5", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcc_s1-32bit-debuginfo", rpm:"libgcc_s1-32bit-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgfortran5-32bit", rpm:"libgfortran5-32bit~10.2.1+git583~1.3.5", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgfortran5-32bit-debuginfo", rpm:"libgfortran5-32bit-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgo16-32bit", rpm:"libgo16-32bit~10.2.1+git583~1.3.5", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgo16-32bit-debuginfo", rpm:"libgo16-32bit-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgomp1-32bit", rpm:"libgomp1-32bit~10.2.1+git583~1.3.5", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgomp1-32bit-debuginfo", rpm:"libgomp1-32bit-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libitm1-32bit", rpm:"libitm1-32bit~10.2.1+git583~1.3.5", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libitm1-32bit-debuginfo", rpm:"libitm1-32bit-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libobjc4-32bit", rpm:"libobjc4-32bit~10.2.1+git583~1.3.5", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libobjc4-32bit-debuginfo", rpm:"libobjc4-32bit-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6-32bit", rpm:"libstdc++6-32bit~10.2.1+git583~1.3.5", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6-32bit-debuginfo", rpm:"libstdc++6-32bit-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6-pp-gcc10-32bit", rpm:"libstdc++6-pp-gcc10-32bit~10.2.1+git583~1.3.5", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libubsan1-32bit", rpm:"libubsan1-32bit~10.2.1+git583~1.3.5", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libubsan1-32bit-debuginfo", rpm:"libubsan1-32bit-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libatomic1-32bit-debuginfo", rpm:"libatomic1-32bit-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquadmath0-32bit", rpm:"libquadmath0-32bit~10.2.1+git583~1.3.5", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquadmath0-32bit-debuginfo", rpm:"libquadmath0-32bit-debuginfo~10.2.1+git583~1.3.5", rls:"SLES12.0SP2"))) {
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
