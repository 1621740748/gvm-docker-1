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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.2403.1");
  script_cve_id("CVE-2018-14349", "CVE-2018-14350", "CVE-2018-14352", "CVE-2018-14353", "CVE-2018-14354", "CVE-2018-14355", "CVE-2018-14356", "CVE-2018-14357", "CVE-2018-14358", "CVE-2018-14359", "CVE-2018-14362");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:38 +0000 (Wed, 09 Jun 2021)");
  script_version("2021-07-22T02:21:52+0000");
  script_tag(name:"last_modification", value:"2021-07-22 02:21:52 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-05-20 01:47:00 +0000 (Wed, 20 May 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:2403-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4|SLES11\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:2403-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20182403-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mutt' package(s) announced via the SUSE-SU-2018:2403-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for mutt fixes the following issues:
Security issues fixed:
- CVE-2018-14352: Fix imap_quote_string in imap/util.c that does not leave
 room for quote characters (bsc#1101582).
- CVE-2018-14353: Fix imap_quote_string in imap/util.c that has an integer
 underflow (bsc#1101581).
- CVE-2018-14362: Fix pop.c that does not forbid characters that may have
 unsafe interaction with message-cache pathnames (bsc#1101567).
- CVE-2018-14354: Fix arbitrary command execution from remote IMAP servers
 via backquote characters (bsc#1101578).
- CVE-2018-14356: Fix pop.c that mishandles a zero-length UID
 (bsc#1101576).
- CVE-2018-14355: Fix imap/util.c that mishandles '..' directory traversal
 in a mailbox name (bsc#1101577).
- CVE-2018-14349: Fix imap/command.c that mishandles a NO response without
 a message (bsc#1101589).
- CVE-2018-14350: Fix imap/message.c that has a stack-based buffer
 overflow for a FETCH response with along INTERNALDATE field
 (bsc#1101588).
- CVE-2018-14357: Fix that remote IMAP servers are allowed to execute
 arbitrary commands via backquote characters (bsc#1101573).
- CVE-2018-14359: Fix buffer overflow via base64 data (bsc#1101570).
- CVE-2018-14358: Fix imap/message.c that has a stack-based buffer
 overflow for a FETCH response with along RFC822.SIZE field (bsc#1101571).
Bug fixes:
- bsc#936807: On entering a 70 character subject line in mutt, a tab is
 added to the text after 67 characters.");

  script_tag(name:"affected", value:"'mutt' package(s) on SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Server 11-SP3, SUSE Linux Enterprise Point of Sale 11-SP3, SUSE Linux Enterprise Debuginfo 11-SP4, SUSE Linux Enterprise Debuginfo 11-SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"mutt", rpm:"mutt~1.5.17~42.43.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES11.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"mutt", rpm:"mutt~1.5.17~42.43.1", rls:"SLES11.0SP3"))) {
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
