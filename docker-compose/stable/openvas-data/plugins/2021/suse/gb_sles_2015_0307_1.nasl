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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.0307.1");
  script_cve_id("CVE-2015-0559", "CVE-2015-0560", "CVE-2015-0561", "CVE-2015-0562", "CVE-2015-0563", "CVE-2015-0564");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2021-07-22T02:21:52+0000");
  script_tag(name:"last_modification", value:"2021-07-22 02:21:52 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:0307-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:0307-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20150307-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wireshark' package(s) announced via the SUSE-SU-2015:0307-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update fixes the following security issues:

- The following vulnerabilities allowed Wireshark to be crashed by
 injecting a malformed packet onto the wire or by convincing someone to
 read a malformed packet trace file.
 + The WCCP dissector could crash wnpa-sec-2015-01 CVE-2015-0559
 CVE-2015-0560 [boo#912365]
 + The LPP dissector could crash. wnpa-sec-2015-02 CVE-2015-0561
 [boo#912368]
 + The DEC DNA Routing Protocol dissector could crash. wnpa-sec-2015-03
 CVE-2015-0562 [boo#912369]
 + The SMTP dissector could crash. wnpa-sec-2015-04 CVE-2015-0563
 [boo#912370]
 + Wireshark could crash while decypting TLS/SSL sessions.
 wnpa-sec-2015-05 CVE-2015-0564 [boo#912372]");

  script_tag(name:"affected", value:"'wireshark' package(s) on SUSE Linux Enterprise Software Development Kit 12, SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Desktop 12.");

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

  if(!isnull(res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~1.10.12~4.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-debuginfo", rpm:"wireshark-debuginfo~1.10.12~4.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-debugsource", rpm:"wireshark-debugsource~1.10.12~4.1", rls:"SLES12.0"))) {
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
