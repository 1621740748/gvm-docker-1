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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.0053.1");
  script_cve_id("CVE-2018-15686", "CVE-2018-16864", "CVE-2018-16865");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2021-07-30T02:23:55+0000");
  script_tag(name:"last_modification", value:"2021-07-30 02:23:55 +0000 (Fri, 30 Jul 2021)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-28 16:33:00 +0000 (Wed, 28 Jul 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:0053-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:0053-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20190053-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'systemd' package(s) announced via the SUSE-SU-2019:0053-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for systemd fixes the following issues:
Fix security vulnerabilities CVE-2018-16864 and CVE-2018-16865
 (bsc#1120323): Both issues were memory corruptions via
 attacker-controlled alloca which could have been used to gain root
 privileges by a local attacker.
Fix security vulnerability CVE-2018-15686 (bsc#1113665): A vulnerability
 in unit_deserialize of systemd used to allow an attacker to supply
 arbitrary state across systemd re-execution via NotifyAccess. This could
 have been used to improperly influence systemd execution and possibly
 lead to root privilege escalation.
Remedy 2048 character line-length limit in systemd-sysctl code that
 would cause parser failures if /etc/sysctl.conf contained lines that
 exceeded this length (bsc#1071558).
Fix a bug in systemd's core timer code that would cause timer looping
 under certain conditions, resulting in hundreds of syslog messages being
 written to the journal (bsc#1068588).");

  script_tag(name:"affected", value:"'systemd' package(s) on SUSE Linux Enterprise Server 12.");

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

  if(!isnull(res = isrpmvuln(pkg:"libgudev-1_0-0", rpm:"libgudev-1_0-0~210~70.74.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgudev-1_0-0-debuginfo", rpm:"libgudev-1_0-0-debuginfo~210~70.74.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgudev-1_0-devel", rpm:"libgudev-1_0-devel~210~70.74.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudev-devel", rpm:"libudev-devel~210~70.74.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudev1", rpm:"libudev1~210~70.74.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudev1-debuginfo", rpm:"libudev1-debuginfo~210~70.74.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd", rpm:"systemd~210~70.74.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-debuginfo", rpm:"systemd-debuginfo~210~70.74.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-debugsource", rpm:"systemd-debugsource~210~70.74.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-devel", rpm:"systemd-devel~210~70.74.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-sysvinit", rpm:"systemd-sysvinit~210~70.74.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GUdev-1_0", rpm:"typelib-1_0-GUdev-1_0~210~70.74.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"udev", rpm:"udev~210~70.74.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"udev-debuginfo", rpm:"udev-debuginfo~210~70.74.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgudev-1_0-0-32bit", rpm:"libgudev-1_0-0-32bit~210~70.74.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgudev-1_0-0-debuginfo-32bit", rpm:"libgudev-1_0-0-debuginfo-32bit~210~70.74.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudev1-32bit", rpm:"libudev1-32bit~210~70.74.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudev1-debuginfo-32bit", rpm:"libudev1-debuginfo-32bit~210~70.74.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-32bit", rpm:"systemd-32bit~210~70.74.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-debuginfo-32bit", rpm:"systemd-debuginfo-32bit~210~70.74.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-bash-completion", rpm:"systemd-bash-completion~210~70.74.1", rls:"SLES12.0"))) {
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
