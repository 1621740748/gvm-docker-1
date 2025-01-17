# Copyright (C) 2013 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) of their respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.850412");
  script_version("2020-01-31T08:23:39+0000");
  script_tag(name:"last_modification", value:"2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)");
  script_tag(name:"creation_date", value:"2013-03-11 18:29:30 +0530 (Mon, 11 Mar 2013)");
  script_cve_id("CVE-2013-0169", "CVE-2013-1486");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"openSUSE-SU", value:"2013:0378-1");
  script_name("openSUSE: Security Advisory for java-1_6_0-openjdk (openSUSE-SU-2013:0378-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1_6_0-openjdk'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSE11\.4");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"affected", value:"java-1_6_0-openjdk on openSUSE 11.4");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"insight", value:"java-1_6_0-openjdk was updated to IcedTea 1.12.3
  (bnc#804654)  containing security and bugfixes:

  * Security fixes

  - S8006446: Restrict MBeanServer access (CVE-2013-1486)

  - S8006777: Improve TLS handling of invalid messages
  Lucky 13 (CVE-2013-0169)

  - S8007688: Blacklist known bad certificate (issued by
  DigiCert)

  * Backports

  - S8007393: Possible race condition after JDK-6664509

  - S8007611: logging behavior in applet changed

  * Bug fixes

  - PR1319: Support GIF lib v5.");

  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2013-03/msg00002.html");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSE11.4") {
  if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-openjdk", rpm:"java-1_6_0-openjdk~1.6.0.0_b27.1.12.3~29.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-openjdk-debuginfo", rpm:"java-1_6_0-openjdk-debuginfo~1.6.0.0_b27.1.12.3~29.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-openjdk-debugsource", rpm:"java-1_6_0-openjdk-debugsource~1.6.0.0_b27.1.12.3~29.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-openjdk-demo", rpm:"java-1_6_0-openjdk-demo~1.6.0.0_b27.1.12.3~29.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-openjdk-demo-debuginfo", rpm:"java-1_6_0-openjdk-demo-debuginfo~1.6.0.0_b27.1.12.3~29.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-openjdk-devel", rpm:"java-1_6_0-openjdk-devel~1.6.0.0_b27.1.12.3~29.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-openjdk-devel-debuginfo", rpm:"java-1_6_0-openjdk-devel-debuginfo~1.6.0.0_b27.1.12.3~29.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-openjdk-javadoc", rpm:"java-1_6_0-openjdk-javadoc~1.6.0.0_b27.1.12.3~29.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-openjdk-src", rpm:"java-1_6_0-openjdk-src~1.6.0.0_b27.1.12.3~29.1", rls:"openSUSE11.4"))) {
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
