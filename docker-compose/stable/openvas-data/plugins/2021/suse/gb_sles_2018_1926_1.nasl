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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.1926.1");
  script_cve_id("CVE-2018-3639", "CVE-2018-3640");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:43 +0000 (Wed, 09 Jun 2021)");
  script_version("2021-07-22T02:21:52+0000");
  script_tag(name:"last_modification", value:"2021-07-22 02:21:52 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:1926-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:1926-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20181926-1/");
  script_xref(name:"URL", value:"https://downloadcenter.intel.com/download/27945/Linux-Processor-Microcode-D");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ucode-intel' package(s) announced via the SUSE-SU-2018:1926-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ucode-intel fixes the following issues:
The microcode bundles was updated to the 20180703 release For the listed CPU chipsets this fixes CVE-2018-3640 (Spectre v3a) and helps mitigating CVE-2018-3639 (Spectre v4) (bsc#1100147 bsc#1087082 bsc#1087083).
More information on:
[link moved to references] ata-File Following chipsets are fixed in this round:
Model Stepping F-MO-S/PI Old->New
---- updated platforms ------------------------------------
SNB-EP C1 6-2d-6/6d 0000061c->0000061d Xeon E5 SNB-EP C2 6-2d-7/6d 00000713->00000714 Xeon E5 IVT C0 6-3e-4/ed 0000042c->0000042d Xeon E5 v2, Core i7-4960X/4930K/4820K IVT D1 6-3e-7/ed 00000713->00000714 Xeon E5 v2 HSX-E/EP/4S C0 6-3f-2/6f 0000003c->0000003d Xeon E5 v3 HSX-EX E0 6-3f-4/80 00000011->00000012 Xeon E7 v3 SKX-SP/D/W/X H0 6-55-4/b7 02000043->0200004d Xeon Bronze 31xx, Silver 41xx, Gold 51xx/61xx Platinum 81xx, D/W-21xx, Core i9-7xxxX BDX-DE A1 6-56-5/10 0e000009->0e00000a Xeon D-15x3N BDX-ML B/M/R0 6-4f-1/ef 0b00002c->0b00002e Xeon E5/E7 v4, Core i7-69xx/68xx");

  script_tag(name:"affected", value:"'ucode-intel' package(s) on SUSE Linux Enterprise Module for Basesystem 15.");

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

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"ucode-intel", rpm:"ucode-intel~20180703~3.3.1", rls:"SLES15.0"))) {
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
