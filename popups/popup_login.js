$(function() {
	var global = chrome.extension.getBackgroundPage();

	chrome.tabs.query({"active": true, "windowId": chrome.windows.WINDOW_ID_CURRENT}, function(tabs) {
		if (tabs.length === 0)
			return; // For example: only the background devtools or a popup are opened
		var tab = tabs[0];

		console.log(global.page.tabs[tab.id]);

		var logins = global.page.tabs[tab.id].loginList;
		var ul = document.getElementById("login-list");
		for (var i = 0; i < logins.length; i++) {
			var li = document.createElement("li");
			var a = document.createElement("a");
			a.textContent = logins[i];
			li.style.padding = "10px";
			li.appendChild(a);
			a.setAttribute("id", "" + i);
			a.addEventListener('click', function(e) {
				var id = e.target.id;
				chrome.tabs.sendMessage(tab.id, {
					action: 'fill_user_pass_with_specific_login',
					id: id
				});
				close();
			});
			var clip = document.createElement("a");
			var clip_img = document.createElement("img");
			clip_img.src = "../images/clipboard-flat.svg";
			clip_img.width = 32;
			clip_img.height = 32;
			clip_img.style.paddingTop = "10px";
			clip_img.setAttribute("id", ""+i);
			clip.appendChild(clip_img);
			li.append(clip);
			clip.setAttribute("id", ""+i);
			clip.addEventListener('click', function(e) {
				var id = e.target.id;
				console.log('id='+id);
				chrome.tabs.sendMessage(tab.id, {
					action: 'copy_pass_to_clipboard',
					id: id
				});
				close();
			});
			ul.appendChild(li);
		}
	});
});