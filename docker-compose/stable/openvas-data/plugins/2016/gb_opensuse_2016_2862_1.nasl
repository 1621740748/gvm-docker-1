# Copyright (C) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.851436");
  script_version("2020-01-31T08:23:39+0000");
  script_tag(name:"last_modification", value:"2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)");
  script_tag(name:"creation_date", value:"2016-11-20 05:37:48 +0100 (Sun, 20 Nov 2016)");
  script_cve_id("CVE-2016-5542", "CVE-2016-5554", "CVE-2016-5556", "CVE-2016-5568",
                "CVE-2016-5573", "CVE-2016-5582", "CVE-2016-5597");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("openSUSE: Security Advisory for java-1_8_0-openjdk (openSUSE-SU-2016:2862-1)");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"OpenJDK java-1_8_0-openjdk was updated to jdk8u111 (icedtea 3.2.0) to fix
  the following issues:

  * Security fixes
  + S8146490: Direct indirect CRL checks
  + S8151921: Improved page resolution
  + S8155968: Update command line options
  + S8155973, CVE-2016-5542: Tighten jar checks (boo#1005522)
  + S8156794: Extend data sharing
  + S8157176: Improved classfile parsing
  + S8157739, CVE-2016-5554: Classloader Consistency Checking
  (boo#1005523)
  + S8157749: Improve handling of DNS error replies
  + S8157753: Audio replay enhancement
  + S8157759: LCMS Transform Sampling Enhancement
  + S8157764: Better handling of interpolation plugins
  + S8158302: Handle contextual glyph substitutions
  + S8158993, CVE-2016-5568: Service Menu services (boo#1005525)
  + S8159495: Fix index offsets
  + S8159503: Amend Annotation Actions
  + S8159511: Stack map validation
  + S8159515: Improve indy validation
  + S8159519, CVE-2016-5573: Reformat JDWP messages (boo#1005526)
  + S8160090: Better signature handling in pack200
  + S8160094: Improve pack200 layout
  + S8160098: Clean up color profiles
  + S8160591, CVE-2016-5582: Improve internal array handling
  (boo#1005527)
  + S8160838, CVE-2016-5597: Better HTTP service (boo#1005528)
  + PR3206, RH1367357: lcms2: Out-of-bounds read in Type_MLU_Read()
  + CVE-2016-5556 (boo#1005524)

  * New features
  + PR1370: Provide option to build without debugging
  + PR1375: Provide option to strip and link debugging info after build
  + PR1537: Handle alternative Kerberos credential cache locations
  + PR1978: Allow use of system PCSC
  + PR2445: Support system libsctp
  + PR3182: Support building without pre-compiled headers
  + PR3183: Support Fedora/RHEL system crypto policy
  + PR3221: Use pkgconfig to detect Kerberos CFLAGS and libraries

  * Import of OpenJDK 8 u102 build 14
  + S4515292: ReferenceType.isStatic() returns true for arrays
  + S4858370: JDWP: Memory Leak: GlobalRefs never deleted when
  processing invokeMethod command
  + S6976636: JVM/TI test ex03t001 fails assertion
  + S7185591: jcmd-big-script.sh ERROR: could not find app's Java pid.
  + S8017462: G1: guarantee fails with UseDynamicNumberOfGCThreads
  + S8034168: ThreadMXBean/Locks.java failed, blocked on wrong
  object
  + S8036006: [TESTBUG] sun/tools/native2ascii/NativeErrors.java fails:
  Process exit code was 0, but error was expected.
  + S8041781: Need new regression tests for PBE keys
  + S8041787: Need new regressions tests for buffer handling for PBE
  algorithms
  + S8043836: Need new tests for AES cipher
  + S8044199: Tests for RSA keys and key specifications
  +  ...

  Description truncated, please see the referenced URL(s) for more information.");

  script_tag(name:"affected", value:"java-1_8_0-openjdk on openSUSE 13.2");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"openSUSE-SU", value:"2016:2862-1");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1_8_0-openjdk'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSE13\.2");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSE13.2")
{

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk", rpm:"java-1_8_0-openjdk~1.8.0.111~33.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-accessibility", rpm:"java-1_8_0-openjdk-accessibility~1.8.0.111~33.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-debuginfo", rpm:"java-1_8_0-openjdk-debuginfo~1.8.0.111~33.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-debugsource", rpm:"java-1_8_0-openjdk-debugsource~1.8.0.111~33.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-demo", rpm:"java-1_8_0-openjdk-demo~1.8.0.111~33.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-demo-debuginfo", rpm:"java-1_8_0-openjdk-demo-debuginfo~1.8.0.111~33.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-devel", rpm:"java-1_8_0-openjdk-devel~1.8.0.111~33.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-devel-debuginfo", rpm:"java-1_8_0-openjdk-devel-debuginfo~1.8.0.111~33.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-headless", rpm:"java-1_8_0-openjdk-headless~1.8.0.111~33.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-headless-debuginfo", rpm:"java-1_8_0-openjdk-headless-debuginfo~1.8.0.111~33.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-src", rpm:"java-1_8_0-openjdk-src~1.8.0.111~33.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-javadoc", rpm:"java-1_8_0-openjdk-javadoc~1.8.0.111~33.1", rls:"openSUSE13.2"))) {
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
