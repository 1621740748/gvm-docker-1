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
  script_oid("1.3.6.1.4.1.25623.1.0.851411");
  script_version("2020-01-31T08:23:39+0000");
  script_tag(name:"last_modification", value:"2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)");
  script_tag(name:"creation_date", value:"2016-10-15 05:53:15 +0200 (Sat, 15 Oct 2016)");
  script_cve_id("CVE-2016-7796");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("openSUSE: Security Advisory for systemd (openSUSE-SU-2016:2539-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'systemd'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for systemd fixes the following security issue:

  - CVE-2016-7796: A zero-length message received over systemd's
  notification socket could make manager_dispatch_notify_fd() return an
  error and, as a side effect, disable the notification handler
  completely. As the notification socket is world-writable, this could
  have allowed a local user to perform a denial-of-service attack against
  systemd. (bsc#1001765)

  Additionally, the following non-security fixes are included:

  - Fix HMAC calculation when appending a data object to journal.
  (bsc#1000435)

  - Never accept file descriptors from file systems with mandatory locking
  enabled. (bsc#954374)

  - Do not warn about missing install info with 'preset'. (bsc#970293)

  - Save /run/systemd/users/UID before starting user@.service. (bsc#996269)

  - Make sure that /var/lib/systemd/sysv-convert/database is always
  initialized. (bsc#982211)

  - Remove daylight saving time handling and tzfile parser. (bsc#990074)

  - Make sure directory watch is started before cryptsetup. (bsc#987173)

  - Introduce sd_pid_notify() and sd_pid_notifyf() APIs. (bsc#987857)

  - Set KillMode=mixed for our daemons that fork worker processes.

  - Add nosuid and nodev options to tmp.mount.

  - Don't start console-getty.service when /dev/console is missing.
  (bsc#982251)

  - Correct segmentation fault in udev/path_id due to missing NULL check.
  (bsc#982210)

  This update was imported from the SUSE:SLE-12-SP1:Update update project.");

  script_tag(name:"affected", value:"systemd on openSUSE Leap 42.1");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"openSUSE-SU", value:"2016:2539-1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.1");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSELeap42.1") {
  if(!isnull(res = isrpmvuln(pkg:"libgudev-1_0-0", rpm:"libgudev-1_0-0~210~98.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgudev-1_0-0-debuginfo", rpm:"libgudev-1_0-0-debuginfo~210~98.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgudev-1_0-devel", rpm:"libgudev-1_0-devel~210~98.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudev-devel", rpm:"libudev-devel~210~98.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudev-mini-devel", rpm:"libudev-mini-devel~210~98.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudev-mini1", rpm:"libudev-mini1~210~98.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudev-mini1-debuginfo", rpm:"libudev-mini1-debuginfo~210~98.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudev1", rpm:"libudev1~210~98.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudev1-debuginfo", rpm:"libudev1-debuginfo~210~98.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-myhostname", rpm:"nss-myhostname~210~98.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-myhostname-debuginfo", rpm:"nss-myhostname-debuginfo~210~98.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd", rpm:"systemd~210~98.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-debuginfo", rpm:"systemd-debuginfo~210~98.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-debugsource", rpm:"systemd-debugsource~210~98.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-devel", rpm:"systemd-devel~210~98.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-journal-gateway", rpm:"systemd-journal-gateway~210~98.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-journal-gateway-debuginfo", rpm:"systemd-journal-gateway-debuginfo~210~98.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-logger", rpm:"systemd-logger~210~98.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-mini", rpm:"systemd-mini~210~98.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-mini-debuginfo", rpm:"systemd-mini-debuginfo~210~98.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-mini-debugsource", rpm:"systemd-mini-debugsource~210~98.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-mini-devel", rpm:"systemd-mini-devel~210~98.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-mini-sysvinit", rpm:"systemd-mini-sysvinit~210~98.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-sysvinit", rpm:"systemd-sysvinit~210~98.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GUdev-1_0", rpm:"typelib-1_0-GUdev-1_0~210~98.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"udev", rpm:"udev~210~98.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"udev-debuginfo", rpm:"udev-debuginfo~210~98.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"udev-mini", rpm:"udev-mini~210~98.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"udev-mini-debuginfo", rpm:"udev-mini-debuginfo~210~98.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-bash-completion", rpm:"systemd-bash-completion~210~98.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgudev-1_0-0-32bit", rpm:"libgudev-1_0-0-32bit~210~98.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgudev-1_0-0-debuginfo-32bit", rpm:"libgudev-1_0-0-debuginfo-32bit~210~98.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudev1-32bit", rpm:"libudev1-32bit~210~98.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudev1-debuginfo-32bit", rpm:"libudev1-debuginfo-32bit~210~98.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-myhostname-32bit", rpm:"nss-myhostname-32bit~210~98.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-myhostname-debuginfo-32bit", rpm:"nss-myhostname-debuginfo-32bit~210~98.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-32bit", rpm:"systemd-32bit~210~98.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-debuginfo-32bit", rpm:"systemd-debuginfo-32bit~210~98.1", rls:"openSUSELeap42.1"))) {
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
