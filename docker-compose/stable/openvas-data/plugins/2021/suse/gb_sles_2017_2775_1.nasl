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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.2775.1");
  script_cve_id("CVE-2017-1000112", "CVE-2017-15274", "CVE-2017-7645", "CVE-2017-9242");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2021-07-22T02:21:52+0000");
  script_tag(name:"last_modification", value:"2021-07-22 02:21:52 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-11-30 21:33:00 +0000 (Fri, 30 Nov 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:2775-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:2775-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20172775-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel Live Patch 27 for SLE 12' package(s) announced via the SUSE-SU-2017:2775-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for the Linux Kernel 3.12.61-52_92 fixes several issues.
The following security bugs were fixed:
- CVE-2017-15274: security/keys/keyctl.c in the Linux kernel did not
 consider the case of a NULL payload in conjunction with a nonzero length
 value, which allowed local users to cause a denial of service (NULL
 pointer dereference and OOPS) via a crafted add_key or keyctl system
 call (bsc#1045327).
- CVE-2017-1000112: Updated patch for this issue to be in sync with the
 other livepatches. Description of the issue: Prevent race condition in
 net-packet code that could have been exploited by unprivileged users to
 gain root access (bsc#1052368, bsc#1052311).
- CVE-2017-9242: The __ip6_append_data function in net/ipv6/ip6_output.c
 was too late in checking whether an overwrite of an skb data structure
 may occur, which allowed local users to cause a denial of service
 (system crash) via crafted system calls (bsc#1042892).
- CVE-2017-7645: The NFSv2/NFSv3 server in the nfsd subsystem allowed
 remote attackers to cause a denial of service (system crash) via a long
 RPC reply (bsc#1046191).");

  script_tag(name:"affected", value:"'Linux Kernel Live Patch 27 for SLE 12' package(s) on SUSE Linux Enterprise Server 12.");

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

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-3_12_61-52_92-default", rpm:"kgraft-patch-3_12_61-52_92-default~2~4.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-3_12_61-52_92-xen", rpm:"kgraft-patch-3_12_61-52_92-xen~2~4.1", rls:"SLES12.0"))) {
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
