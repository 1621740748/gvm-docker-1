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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.1183.1");
  script_cve_id("CVE-2018-7158", "CVE-2018-7159", "CVE-2018-7160");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:45 +0000 (Wed, 09 Jun 2021)");
  script_version("2021-07-22T02:21:52+0000");
  script_tag(name:"last_modification", value:"2021-07-22 02:21:52 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:1183-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:1183-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20181183-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nodejs6' package(s) announced via the SUSE-SU-2018:1183-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for nodejs6 fixes the following issues:
- Fix some node-gyp permissions
- New upstream LTS release 6.14.1:
 * Security fixes:
 + CVE-2018-7160: Fix for inspector DNS rebinding vulnerability
 (bsc#1087463)
 + CVE-2018-7158: Fix for 'path' module regular expression denial of
 service (bsc#1087459)
 + CVE-2018-7159: Reject spaces in HTTP Content-Length header values
 (bsc#1087453)
- New upstream LTS release 6.13.1:
 * http,tls: better support for IPv6 addresses
 * console: added console.count() and console.clear()
 * crypto:
 + expose ECDH class
 + added cypto.randomFill() and crypto.randomFillSync()
 + warn on invalid authentication tag length
 * deps: upgrade libuv to 1.16.1
 * dgram: added socket.setMulticastInterface()
 * http: add agent.keepSocketAlive and agent.reuseSocket as to allow
 overridable keep-alive behavior of Agent
 * lib: return this from net.Socket.end()
 * module: add builtinModules api that provides list of all builtin
 modules in Node
 * net: return this from getConnections()
 * promises: more robust stringification for unhandled rejections
 * repl: improve require() autocompletion
 * src:
 + add openssl-system-ca-path configure option
 + add --use-bundled-ca --use-openssl-ca check
 + add process.ppid
 * tls: accept lookup option for tls.connect()
 * tools,build: a new macOS installer!
 * url: WHATWG URL api support
 * util: add %i and %f formatting specifiers
- remove any old manpage files in %pre from before update-alternatives
 were used to manage symlinks to these manpages.
- Add Recommends and BuildRequire on python2 for npm. node-gyp requires
 this old version of python for now. This is only needed for binary
 modules.
- even on recent codestreams there is no binutils gold on s390
 only on s390x
- New upstream LTS release 6.12.3:
 * v8: profiler-related fixes
 * mostly documentation and test related changes
- Enable CI tests in %check target");

  script_tag(name:"affected", value:"'nodejs6' package(s) on SUSE OpenStack Cloud 7, SUSE Linux Enterprise Module for Web Scripting 12, SUSE Enterprise Storage 4.");

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

  if(!isnull(res = isrpmvuln(pkg:"nodejs6", rpm:"nodejs6~6.14.1~11.12.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs6-debuginfo", rpm:"nodejs6-debuginfo~6.14.1~11.12.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs6-debugsource", rpm:"nodejs6-debugsource~6.14.1~11.12.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs6-devel", rpm:"nodejs6-devel~6.14.1~11.12.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"npm6", rpm:"npm6~6.14.1~11.12.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs6-docs", rpm:"nodejs6-docs~6.14.1~11.12.1", rls:"SLES12.0"))) {
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
