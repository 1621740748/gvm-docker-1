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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.2080.1");
  script_cve_id("CVE-2015-8935", "CVE-2016-5399", "CVE-2016-5766", "CVE-2016-5767", "CVE-2016-5769", "CVE-2016-5772", "CVE-2016-6288", "CVE-2016-6289", "CVE-2016-6290", "CVE-2016-6291", "CVE-2016-6296", "CVE-2016-6297");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:05 +0000 (Wed, 09 Jun 2021)");
  script_version("2021-07-22T02:21:52+0000");
  script_tag(name:"last_modification", value:"2021-07-22 02:21:52 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-11-28 20:29:00 +0000 (Mon, 28 Nov 2016)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:2080-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:2080-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20162080-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php5' package(s) announced via the SUSE-SU-2016:2080-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"php5 was updated to fix the following security issues:
- CVE-2016-6297: Stack-based buffer overflow vulnerability in
 php_stream_zip_opener (bsc#991426).
- CVE-2016-6291: Out-of-bounds access in exif_process_IFD_in_MAKERNOTE
 (bsc#991427).
- CVE-2016-6289: Integer overflow leads to buffer overflow in
 virtual_file_ex (bsc#991428).
- CVE-2016-6290: Use after free in unserialize() with Unexpected Session
 Deserialization (bsc#991429).
- CVE-2016-5399: Improper error handling in bzread() (bsc#991430).
- CVE-2016-6288: Buffer over-read in php_url_parse_ex (bsc#991433).
- CVE-2016-6296: Heap buffer overflow vulnerability in simplestring_addn
 in simplestring.c (bsc#991437).
- CVE-2016-5769: Mcrypt: Heap Overflow due to integer overflows
 (bsc#986388).
- CVE-2015-8935: XSS in header() with Internet Explorer (bsc#986004).
- CVE-2016-5772: Double free corruption in wddx_deserialize (bsc#986244).
- CVE-2016-5766: Integer Overflow in _gd2GetHeader() resulting in heap
 overflow (bsc#986386).
- CVE-2016-5767: Integer Overflow in gdImagePaletteToTrueColor() resulting
 in heap overflow (bsc#986393).");

  script_tag(name:"affected", value:"'php5' package(s) on SUSE Linux Enterprise Server 11-SP2, SUSE Linux Enterprise Debuginfo 11-SP2.");

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

if(release == "SLES11.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"apache2-mod_php5", rpm:"apache2-mod_php5~5.2.14~0.7.30.89.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5", rpm:"php5~5.2.14~0.7.30.89.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-bcmath", rpm:"php5-bcmath~5.2.14~0.7.30.89.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-bz2", rpm:"php5-bz2~5.2.14~0.7.30.89.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-calendar", rpm:"php5-calendar~5.2.14~0.7.30.89.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-ctype", rpm:"php5-ctype~5.2.14~0.7.30.89.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-curl", rpm:"php5-curl~5.2.14~0.7.30.89.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-dba", rpm:"php5-dba~5.2.14~0.7.30.89.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-dbase", rpm:"php5-dbase~5.2.14~0.7.30.89.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-dom", rpm:"php5-dom~5.2.14~0.7.30.89.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-exif", rpm:"php5-exif~5.2.14~0.7.30.89.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-fastcgi", rpm:"php5-fastcgi~5.2.14~0.7.30.89.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-ftp", rpm:"php5-ftp~5.2.14~0.7.30.89.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-gd", rpm:"php5-gd~5.2.14~0.7.30.89.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-gettext", rpm:"php5-gettext~5.2.14~0.7.30.89.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-gmp", rpm:"php5-gmp~5.2.14~0.7.30.89.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-hash", rpm:"php5-hash~5.2.14~0.7.30.89.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-iconv", rpm:"php5-iconv~5.2.14~0.7.30.89.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-json", rpm:"php5-json~5.2.14~0.7.30.89.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-ldap", rpm:"php5-ldap~5.2.14~0.7.30.89.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-mbstring", rpm:"php5-mbstring~5.2.14~0.7.30.89.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-mcrypt", rpm:"php5-mcrypt~5.2.14~0.7.30.89.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-mysql", rpm:"php5-mysql~5.2.14~0.7.30.89.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-odbc", rpm:"php5-odbc~5.2.14~0.7.30.89.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-openssl", rpm:"php5-openssl~5.2.14~0.7.30.89.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-pcntl", rpm:"php5-pcntl~5.2.14~0.7.30.89.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-pdo", rpm:"php5-pdo~5.2.14~0.7.30.89.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-pear", rpm:"php5-pear~5.2.14~0.7.30.89.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-pgsql", rpm:"php5-pgsql~5.2.14~0.7.30.89.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-pspell", rpm:"php5-pspell~5.2.14~0.7.30.89.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-shmop", rpm:"php5-shmop~5.2.14~0.7.30.89.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-snmp", rpm:"php5-snmp~5.2.14~0.7.30.89.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-soap", rpm:"php5-soap~5.2.14~0.7.30.89.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-suhosin", rpm:"php5-suhosin~5.2.14~0.7.30.89.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-sysvmsg", rpm:"php5-sysvmsg~5.2.14~0.7.30.89.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-sysvsem", rpm:"php5-sysvsem~5.2.14~0.7.30.89.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-sysvshm", rpm:"php5-sysvshm~5.2.14~0.7.30.89.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-tokenizer", rpm:"php5-tokenizer~5.2.14~0.7.30.89.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-wddx", rpm:"php5-wddx~5.2.14~0.7.30.89.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-xmlreader", rpm:"php5-xmlreader~5.2.14~0.7.30.89.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-xmlrpc", rpm:"php5-xmlrpc~5.2.14~0.7.30.89.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-xmlwriter", rpm:"php5-xmlwriter~5.2.14~0.7.30.89.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-xsl", rpm:"php5-xsl~5.2.14~0.7.30.89.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-zip", rpm:"php5-zip~5.2.14~0.7.30.89.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-zlib", rpm:"php5-zlib~5.2.14~0.7.30.89.1", rls:"SLES11.0SP2"))) {
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
