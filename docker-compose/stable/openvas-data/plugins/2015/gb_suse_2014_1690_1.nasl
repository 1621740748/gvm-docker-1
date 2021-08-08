# Copyright (C) 2015 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851069");
  script_version("2020-01-31T07:58:03+0000");
  script_tag(name:"last_modification", value:"2020-01-31 07:58:03 +0000 (Fri, 31 Jan 2020)");
  script_tag(name:"creation_date", value:"2015-10-16 19:22:35 +0200 (Fri, 16 Oct 2015)");
  script_cve_id("CVE-2014-9295", "CVE-2014-9296");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SUSE: Security Advisory for ntp (SUSE-SU-2014:1690-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ntp'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The network timeservice ntp was updated to fix critical security issues
  (bnc#910764, CERT VU#852879)

  * A potential remote code execution problem was found inside ntpd. The
  functions crypto_recv() (when using autokey authentication),
  ctl_putdata(), and configure() where updated to avoid buffer overflows
  that could be exploited. (CVE-2014-9295)

  * Furthermore a problem inside the ntpd error handling was found that is
  missing a return statement. This could also lead to a potentially attack
  vector. (CVE-2014-9296)");

  script_tag(name:"affected", value:"ntp on SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Desktop 12");

  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_xref(name:"SUSE-SU", value:"2014:1690-1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(SLED12\.0SP0|SLES12\.0SP0)");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLED12.0SP0") {
  if(!isnull(res = isrpmvuln(pkg:"ntp", rpm:"ntp~4.2.6p5~31.1", rls:"SLED12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntp-debuginfo", rpm:"ntp-debuginfo~4.2.6p5~31.1", rls:"SLED12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntp-debugsource", rpm:"ntp-debugsource~4.2.6p5~31.1", rls:"SLED12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntp-doc", rpm:"ntp-doc~4.2.6p5~31.1", rls:"SLED12.0SP0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP0") {
  if(!isnull(res = isrpmvuln(pkg:"ntp", rpm:"ntp~4.2.6p5~31.1", rls:"SLES12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntp-debuginfo", rpm:"ntp-debuginfo~4.2.6p5~31.1", rls:"SLES12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntp-debugsource", rpm:"ntp-debugsource~4.2.6p5~31.1", rls:"SLES12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntp-doc", rpm:"ntp-doc~4.2.6p5~31.1", rls:"SLES12.0SP0"))) {
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
