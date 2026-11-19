/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

"use strict";

const { MailNotificationManager } = ChromeUtils.importESModule(
  "resource:///modules/MailNotificationManager.sys.mjs"
);

add_task(async function test_vaultNotificationsStayInThunderbird() {
  const prefs = ["mail.biff.use_system_alert", "alerts.useSystemBackend"];
  for (const pref of prefs) {
    Assert.ok(Services.prefs.prefIsLocked(pref), `${pref} should be locked`);
    Assert.ok(
      Services.prefs.prefHasUserValue(pref),
      `The test profile should contain a saved value for ${pref}`
    );
    Assert.ok(
      !Services.prefs.getBoolPref(pref),
      `A saved preference should not enable ${pref}`
    );
  }

  const folder = { URI: "mailbox://example.invalid/Inbox" };
  const manager = Object.create(MailNotificationManager);
  manager._logger = console;
  let notifiedFolder;
  manager._showCustomizedAlert = value => {
    notifiedFolder = value;
  };
  await manager._fillAlertInfo(folder, [1], 1);
  Assert.equal(notifiedFolder, folder, "New mail should use the in-app alert");
});
