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
  script_oid("1.3.6.1.4.1.25623.1.0.851330");
  script_version("2020-01-31T08:23:39+0000");
  script_tag(name:"last_modification", value:"2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)");
  script_tag(name:"creation_date", value:"2016-06-10 05:23:44 +0200 (Fri, 10 Jun 2016)");
  script_cve_id("CVE-2016-5118");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("openSUSE: Security Advisory for ImageMagick (openSUSE-SU-2016:1534-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ImageMagick'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ImageMagick fixes the following issues:

  - security update:

  * CVE-2016-5118 [boo#982178]
  + ImageMagick-CVE-2016-5118.patch");

  script_tag(name:"affected", value:"ImageMagick on openSUSE 13.2");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"openSUSE-SU", value:"2016:1534-1");
  script_tag(name:"solution_type", value:"VendorFix");
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

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick", rpm:"ImageMagick~6.8.9.8~21.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-debuginfo", rpm:"ImageMagick-debuginfo~6.8.9.8~21.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-debugsource", rpm:"ImageMagick-debugsource~6.8.9.8~21.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-devel", rpm:"ImageMagick-devel~6.8.9.8~21.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-extra", rpm:"ImageMagick-extra~6.8.9.8~21.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-extra-debuginfo", rpm:"ImageMagick-extra-debuginfo~6.8.9.8~21.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagick++-6_Q16-5", rpm:"libMagick++-6_Q16-5~6.8.9.8~21.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagick++-6_Q16-5-debuginfo", rpm:"libMagick++-6_Q16-5-debuginfo~6.8.9.8~21.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagick++-devel", rpm:"libMagick++-devel~6.8.9.8~21.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickCore-6_Q16-2", rpm:"libMagickCore-6_Q16-2~6.8.9.8~21.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickCore-6_Q16-2-debuginfo", rpm:"libMagickCore-6_Q16-2-debuginfo~6.8.9.8~21.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickWand-6_Q16-2", rpm:"libMagickWand-6_Q16-2~6.8.9.8~21.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickWand-6_Q16-2-debuginfo", rpm:"libMagickWand-6_Q16-2-debuginfo~6.8.9.8~21.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-PerlMagick", rpm:"perl-PerlMagick~6.8.9.8~21.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-PerlMagick-debuginfo", rpm:"perl-PerlMagick-debuginfo~6.8.9.8~21.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-doc", rpm:"ImageMagick-doc~6.8.9.8~21.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-devel-32bit", rpm:"ImageMagick-devel-32bit~6.8.9.8~21.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagick++-6_Q16-5-32bit", rpm:"libMagick++-6_Q16-5-32bit~6.8.9.8~21.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagick++-6_Q16-5-debuginfo-32bit", rpm:"libMagick++-6_Q16-5-debuginfo-32bit~6.8.9.8~21.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagick++-devel-32bit", rpm:"libMagick++-devel-32bit~6.8.9.8~21.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickCore-6_Q16-2-32bit", rpm:"libMagickCore-6_Q16-2-32bit~6.8.9.8~21.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickCore-6_Q16-2-debuginfo-32bit", rpm:"libMagickCore-6_Q16-2-debuginfo-32bit~6.8.9.8~21.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickWand-6_Q16-2-32bit", rpm:"libMagickWand-6_Q16-2-32bit~6.8.9.8~21.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickWand-6_Q16-2-debuginfo-32bit", rpm:"libMagickWand-6_Q16-2-debuginfo-32bit~6.8.9.8~21.1", rls:"openSUSE13.2"))) {
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
