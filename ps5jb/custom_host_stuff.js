async function runJailbreak() {
    let postjb = document.getElementById("post-jb-view");
    postjb.style.opacity = "0";
    postjb.style.pointerEvents = "none";
    document.getElementById("run-jb-parent").style.opacity = "0";
    await sleep(500);
    document.getElementById("run-jb-parent").style.display = "none";
    document.getElementById("jb-progress").style.opacity = "1";
    await sleep(500);

    setTimeout(() => {
        poc();
    }, 100);
}

async function switch_to_post_jb_view() {
    // should already be none but just in case
    document.getElementById("run-jb-parent").style.display = "none";

    document.getElementById("jb-progress").style.opacity = "0";
    await sleep(1000);
    document.getElementById("jb-progress").style.display = "none";

    document.getElementById("post-jb-view").style.opacity = "0";
    document.getElementById("post-jb-view").classList.add("opacity-transition");
    document.getElementById("post-jb-view").style.display = "flex";
    document.getElementById("post-jb-view").style.opacity = "1";

    document.getElementById("credits").style.opacity = "0";
    document.getElementById("credits").style.display = "none";

}

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

// unused, the code needs to be in the main exploit function
function create_payload_buttons() {
    for (let i = 0; i < payload_map.length && i < 20; i++) {
        let btn = document.getElementById("payload-" + i);
        btn.onclick = async () => {
            try {
                await load_local_elf(payload_map[i].fileName);
            }
            catch (err) {
                await alert(err);
            }
        };

        let btn_child = btn.children[0];
        btn_child.innerHTML = payload_map[i].displayTitle;

        let btn_child2 = btn.children[1];
        btn_child2.innerHTML = payload_map[i].description;

        btn.style.visibility = "visible";
        btn.style.maxHeight = 'unset';
        btn.classList.remove("hidden-btn");
    }

}

function showToast(message) {
    const toastContainer = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = 'toast';
    toast.textContent = message;

    toastContainer.appendChild(toast);

    // Trigger reflow and enable animation
    toast.offsetHeight;

    toast.classList.add('show');

    setTimeout(() => {
        toast.classList.add('hide');
        toast.addEventListener('transitionend', () => {
            toast.remove();
        });
    }, 2000);
}
