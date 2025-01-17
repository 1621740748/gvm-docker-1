# Copyright (C) 2011 Greenbone Networks GmbH
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2009-November/016328.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880847");
  script_version("2020-03-13T10:06:41+0000");
  script_tag(name:"last_modification", value:"2020-03-13 10:06:41 +0000 (Fri, 13 Mar 2020)");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name:"CESA", value:"2009:1584");
  script_cve_id("CVE-2009-2409", "CVE-2009-3728", "CVE-2009-3869", "CVE-2009-3871", "CVE-2009-3873", "CVE-2009-3874", "CVE-2009-3875", "CVE-2009-3876", "CVE-2009-3877", "CVE-2009-3879", "CVE-2009-3880", "CVE-2009-3881", "CVE-2009-3882", "CVE-2009-3883", "CVE-2009-3884");
  script_name("CentOS Update for java CESA-2009:1584 centos5 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"java on CentOS 5");
  script_tag(name:"insight", value:"These packages provide the OpenJDK 6 Java Runtime Environment and the
  OpenJDK 6 Software Development Kit. The Java Runtime Environment (JRE)
  contains the software and tools that users need to run applications written
  using the Java programming language.

  An integer overflow flaw and buffer overflow flaws were found in the way
  the JRE processed image files. An untrusted applet or application could use
  these flaws to extend its privileges, allowing it to read and write local
  files, as well as to execute local applications with the privileges of the
  user running the applet or application. (CVE-2009-3869, CVE-2009-3871,
  CVE-2009-3873, CVE-2009-3874)

  An information leak was found in the JRE. An untrusted applet or
  application could use this flaw to extend its privileges, allowing it to
  read and write local files, as well as to execute local applications with
  the privileges of the user running the applet or application. (CVE-2009-3881)

  It was discovered that the JRE still accepts certificates with MD2 hash
  signatures, even though MD2 is no longer considered a cryptographically
  strong algorithm. This could make it easier for an attacker to create a
  malicious certificate that would be treated as trusted by the JRE. With
  this update, the JRE disables the use of the MD2 algorithm inside
  signatures by default. (CVE-2009-2409)

  A timing attack flaw was found in the way the JRE processed HMAC digests.
  This flaw could aid an attacker using forged digital signatures to bypass
  authentication checks. (CVE-2009-3875)

  Two denial of service flaws were found in the JRE. These could be exploited
  in server-side application scenarios that process DER-encoded
  (Distinguished Encoding Rules) data. (CVE-2009-3876, CVE-2009-3877)

  An information leak was found in the way the JRE handled color profiles. An
  attacker could use this flaw to discover the existence of files outside of
  the color profiles directory. (CVE-2009-3728)

  A flaw in the JRE with passing arrays to the X11GraphicsDevice API was
  found. An untrusted applet or application could use this flaw to access and
  modify the list of supported graphics configurations. This flaw could also
  lead to sensitive information being leaked to unprivileged code.
  (CVE-2009-3879)

  It was discovered that the JRE passed entire objects to the logging API.
  This could lead to sensitive information being leaked to either untrusted
  or lower-privileged code from an attacker-controlled applet which has
  access to the logging API and is therefore able to manipulate (read and/or
  call) the passed object ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "CentOS5") {
  if(!isnull(res = isrpmvuln(pkg:"java-1.6.0-openjdk", rpm:"java-1.6.0-openjdk~1.6.0.0~1.7.b09.el5", rls:"CentOS5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.6.0-openjdk-demo", rpm:"java-1.6.0-openjdk-demo~1.6.0.0~1.7.b09.el5", rls:"CentOS5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.6.0-openjdk-devel", rpm:"java-1.6.0-openjdk-devel~1.6.0.0~1.7.b09.el5", rls:"CentOS5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.6.0-openjdk-javadoc", rpm:"java-1.6.0-openjdk-javadoc~1.6.0.0~1.7.b09.el5", rls:"CentOS5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.6.0-openjdk-src", rpm:"java-1.6.0-openjdk-src~1.6.0.0~1.7.b09.el5", rls:"CentOS5"))) {
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
