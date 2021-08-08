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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.3180.1");
  script_cve_id("CVE-2019-3688", "CVE-2019-3690");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2021-07-22T02:21:52+0000");
  script_tag(name:"last_modification", value:"2021-07-22 02:21:52 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-20 16:15:00 +0000 (Fri, 20 Nov 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:3180-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP3|SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:3180-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20193180-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'permissions' package(s) announced via the SUSE-SU-2019:3180-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for permissions fixes the following issues:
CVE-2019-3688: Changed wrong ownership in /usr/sbin/pinger to root:squid
 which could have allowed a squid user to gain persistence by changing
 the binary (bsc#1093414).

CVE-2019-3690: Fixed a privilege escalation through untrusted symbolic
 links (bsc#1150734).

Fixed a regression which caused segmentation fault (bsc#1157198).");

  script_tag(name:"affected", value:"'permissions' package(s) on SUSE OpenStack Cloud Crowbar 8, SUSE OpenStack Cloud 8, SUSE OpenStack Cloud 7, SUSE Linux Enterprise Server for SAP 12-SP3, SUSE Linux Enterprise Server for SAP 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server 12-SP2, SUSE Enterprise Storage 5, SUSE CaaS Platform 3.0, HPE Helion Openstack 8.");

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

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"permissions", rpm:"permissions~2015.09.28.1626~17.20.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"permissions-debuginfo", rpm:"permissions-debuginfo~2015.09.28.1626~17.20.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"permissions-debugsource", rpm:"permissions-debugsource~2015.09.28.1626~17.20.1", rls:"SLES12.0SP3"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"permissions", rpm:"permissions~2015.09.28.1626~17.20.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"permissions-debuginfo", rpm:"permissions-debuginfo~2015.09.28.1626~17.20.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"permissions-debugsource", rpm:"permissions-debugsource~2015.09.28.1626~17.20.1", rls:"SLES12.0SP2"))) {
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
