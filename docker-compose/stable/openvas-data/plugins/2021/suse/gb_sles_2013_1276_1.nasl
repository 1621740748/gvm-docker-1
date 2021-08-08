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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2013.1276.1");
  script_cve_id("CVE-2013-2486", "CVE-2013-2487", "CVE-2013-3555", "CVE-2013-3556", "CVE-2013-3557", "CVE-2013-3558", "CVE-2013-3559", "CVE-2013-3560", "CVE-2013-3561", "CVE-2013-3562", "CVE-2013-4074", "CVE-2013-4075", "CVE-2013-4076", "CVE-2013-4077", "CVE-2013-4078", "CVE-2013-4079", "CVE-2013-4080", "CVE-2013-4081", "CVE-2013-4082", "CVE-2013-4083");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:24 +0000 (Wed, 09 Jun 2021)");
  script_version("2021-07-22T02:21:52+0000");
  script_tag(name:"last_modification", value:"2021-07-22 02:21:52 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2013:1276-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES10\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2013:1276-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2013/suse-su-20131276-1/");
  script_xref(name:"URL", value:"http://www.wireshark.org/docs/relnotes/wireshark-1.6.16.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/docs/relnotes/wireshark-1.6.15.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wireshark' package(s) announced via the SUSE-SU-2013:1276-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This wireshark version update to 1.6.16 includes several security and general bug fixes.

[link moved to references] l>

 * The CAPWAP dissector could crash. Discovered by Laurent Butti. (CVE-2013-4074)
 * The HTTP dissector could overrun the stack.
Discovered by David Keeler. (CVE-2013-4081)
 * The DCP ETSI dissector could crash. (CVE-2013-4083)

[link moved to references] l>

 * The ASN.1 BER dissector could crash. ( CVE-2013-3556 CVE-2013-3557 )

The releases also fix various non-security issues.

Additionally, a crash in processing SCTP filters has been fixed. (bug#816887)

Security Issue references:

 * CVE-2013-2486
>
 * CVE-2013-2487
>
 * CVE-2013-3555
>
 * CVE-2013-3556
>
 * CVE-2013-3557
>
 * CVE-2013-3558
>
 * CVE-2013-3559
>
 * CVE-2013-3560
>
 * CVE-2013-3561
>
 * CVE-2013-3562
>
 * CVE-2013-3561
>
 * CVE-2013-3561
>
 * CVE-2013-4074
>
 * CVE-2013-4075
>
 * CVE-2013-4076
>
 * CVE-2013-4077
>
 * CVE-2013-4078
>
 * CVE-2013-4079
>
 * CVE-2013-4080
>
 * CVE-2013-4081
>
 * CVE-2013-4082
>
 * CVE-2013-4083
>");

  script_tag(name:"affected", value:"'wireshark' package(s) on SUSE Linux Enterprise Server 10 SP4, SUSE Linux Enterprise Desktop 10 SP4, SLE SDK 10 SP4.");

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

if(release == "SLES10.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~1.6.16~0.5.5", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-devel", rpm:"wireshark-devel~1.6.16~0.5.5", rls:"SLES10.0SP4"))) {
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
