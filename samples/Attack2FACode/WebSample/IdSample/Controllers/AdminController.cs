//using Microsoft.AspNet.Identity;
//using Microsoft.AspNet.Identity.EntityFramework;
//using System;
//using System.Collections.Generic;
//using System.Threading;
//using System.Threading.Tasks;
//using System.Web;
//using System.Web.Mvc;
//using IdentitySample.Models;

//namespace IdentitySample.Controllers {
//    public class AdminController : Controller {
//        public AdminController() : this(new IdentityManager(new IdentityStore())) { }

//        public AdminController(IdentityManager service)
//        {
//            IdentityStore = service;
//        }

//        public IdentityManager IdentityStore { get; private set; }

//        public ActionResult ListUsers() {
//            ViewBag.Message = "This will list all the users";

//            var db = new DefaultIdentityDbContext();
//            return View(db.Users);
//        }

//        //public async Task<ActionResult> EditUser(string userId) {
//        //    return View(new EditUserModel() { Logins = await IdentityStore.Users.GetLoginsAsync(userId), User = await IdentityStore.Users.FindByIdAsync(userId) });
//        //}
//    }
//}
