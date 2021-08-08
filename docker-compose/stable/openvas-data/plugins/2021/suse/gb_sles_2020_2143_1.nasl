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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.2143.1");
  script_cve_id("CVE-2020-14556", "CVE-2020-14562", "CVE-2020-14573", "CVE-2020-14577", "CVE-2020-14581", "CVE-2020-14583", "CVE-2020-14593", "CVE-2020-14621");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2021-07-22T02:21:52+0000");
  script_tag(name:"last_modification", value:"2021-07-22 02:21:52 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-10 16:15:00 +0000 (Tue, 10 Nov 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:2143-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0|SLES15\.0SP2|SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:2143-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20202143-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-11-openjdk' package(s) announced via the SUSE-SU-2020:2143-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for java-11-openjdk fixes the following issues:

Update to upstream tag jdk-11.0.8+10 (July 2020 CPU, bsc#1174157)
 * Security fixes:
 + JDK-8230613: Better ASCII conversions
 + JDK-8231800: Better listing of arrays
 + JDK-8232014: Expand DTD support
 + JDK-8233234: Better Zip Naming
 + JDK-8233239, CVE-2020-14562: Enhance TIFF support
 + JDK-8233255: Better Swing Buttons
 + JDK-8234032: Improve basic calendar services
 + JDK-8234042: Better factory production of certificates
 + JDK-8234418: Better parsing with CertificateFactory
 + JDK-8234836: Improve serialization handling
 + JDK-8236191: Enhance OID processing
 + JDK-8236867, CVE-2020-14573: Enhance Graal interface handling
 + JDK-8237117, CVE-2020-14556: Better ForkJoinPool behavior
 + JDK-8237592, CVE-2020-14577: Enhance certificate verification
 + JDK-8238002, CVE-2020-14581: Better matrix operations
 + JDK-8238013: Enhance String writing
 + JDK-8238804: Enhance key handling process
 + JDK-8238842: AIOOBE in GIFImageReader.initializeStringTable
 + JDK-8238843: Enhanced font handing
 + JDK-8238920, CVE-2020-14583: Better Buffer support
 + JDK-8238925: Enhance WAV file playback
 + JDK-8240119, CVE-2020-14593: Less Affine Transformations
 + JDK-8240482: Improved WAV file playback
 + JDK-8241379: Update JCEKS support
 + JDK-8241522: Manifest improved jar headers redux
 + JDK-8242136, CVE-2020-14621: Better XML namespace handling
 * Other changes:
 + JDK-6933331: (d3d/ogl) java.lang.IllegalStateException: Buffers have
 not been created
 + JDK-7124307: JSpinner and changing value by mouse
 + JDK-8022574: remove HaltNode code after uncommon trap calls
 + JDK-8039082: [TEST_BUG] Test
 java/awt/dnd/BadSerializationTest/BadSerializationTest.java fails
 + JDK-8040630: Popup menus and tooltips flicker with previous popup
 contents when first shown
 + JDK-8044365: (dc) MulticastSendReceiveTests.java failing with ENOMEM
 when joining group (OS X 10.9)
 + JDK-8048215: [TESTBUG]
 java/lang/management/ManagementFactory/ThreadMXBeanProxy.java
 Expected non-null LockInfo
 + JDK-8051349: nsk/jvmti/scenarios/sampling/SP06/sp06t003 fails in
 nightly
 + JDK-8080353: JShell: Better error message on attempting to add
 default method
 + JDK-8139876: Exclude hanging nsk/stress/stack from execution with
 deoptimization enabled
 + JDK-8146090: java/lang/ref/ReachabilityFenceTest.java fails with
 -XX:+DeoptimizeALot
 + JDK-8153430: jdk regression test MletParserLocaleTest,
 ParserInfiniteLoopTest reduce default timeout
 + JDK-8156207: Resource allocated BitMaps are often cleared
 unnecessarily
 + JDK-8159740: JShell: corralled declarations do not have correct
 source to wrapper mapping
 + JDK-8175984: ICC_Profile has un-needed, not-empty finalize method
 + JDK-8176359: Frame#setMaximizedbounds not working properly in multi
 screen environments
 + JDK-8183369: RFC unconformity of HttpURLConnection with proxy
 + JDK-8187078: ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'java-11-openjdk' package(s) on SUSE Linux Enterprise Server for SAP 15, SUSE Linux Enterprise Server 15, SUSE Linux Enterprise Module for Packagehub Subpackages 15-SP2, SUSE Linux Enterprise Module for Packagehub Subpackages 15-SP1, SUSE Linux Enterprise Module for Basesystem 15-SP2, SUSE Linux Enterprise Module for Basesystem 15-SP1, SUSE Linux Enterprise High Performance Computing 15.");

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

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk", rpm:"java-11-openjdk~11.0.8.0~3.45.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-debuginfo", rpm:"java-11-openjdk-debuginfo~11.0.8.0~3.45.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-debugsource", rpm:"java-11-openjdk-debugsource~11.0.8.0~3.45.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-demo", rpm:"java-11-openjdk-demo~11.0.8.0~3.45.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-devel", rpm:"java-11-openjdk-devel~11.0.8.0~3.45.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-headless", rpm:"java-11-openjdk-headless~11.0.8.0~3.45.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-javadoc", rpm:"java-11-openjdk-javadoc~11.0.8.0~3.45.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk", rpm:"java-11-openjdk~11.0.8.0~3.45.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-debuginfo", rpm:"java-11-openjdk-debuginfo~11.0.8.0~3.45.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-debugsource", rpm:"java-11-openjdk-debugsource~11.0.8.0~3.45.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-demo", rpm:"java-11-openjdk-demo~11.0.8.0~3.45.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-devel", rpm:"java-11-openjdk-devel~11.0.8.0~3.45.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-headless", rpm:"java-11-openjdk-headless~11.0.8.0~3.45.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-javadoc", rpm:"java-11-openjdk-javadoc~11.0.8.0~3.45.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk", rpm:"java-11-openjdk~11.0.8.0~3.45.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-debuginfo", rpm:"java-11-openjdk-debuginfo~11.0.8.0~3.45.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-debugsource", rpm:"java-11-openjdk-debugsource~11.0.8.0~3.45.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-demo", rpm:"java-11-openjdk-demo~11.0.8.0~3.45.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-devel", rpm:"java-11-openjdk-devel~11.0.8.0~3.45.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-headless", rpm:"java-11-openjdk-headless~11.0.8.0~3.45.1", rls:"SLES15.0SP1"))) {
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
