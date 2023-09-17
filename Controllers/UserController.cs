using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using Login_Registration.Models;
using Microsoft.AspNetCore.Identity;
using System.Reflection.Metadata.Ecma335;

namespace Login_Registration.Controllers;

public class UserController : Controller
{
    private readonly ILogger<UserController> _logger;

    private MyContext _context;

    public UserController(ILogger<UserController> logger, MyContext context)
    {
        _logger = logger;
        _context = context;
    }
    [HttpGet("")]
    public IActionResult Index()
    {
        return View();
    }

    [HttpPost("users/register")]
    public IActionResult Register(User newUser)
    {
        if (ModelState.IsValid)
        {

            PasswordHasher<User> Hasher = new();

            newUser.Password = Hasher.HashPassword(newUser, newUser.Password);

            _context.Add(newUser);
            _context.SaveChanges();

            HttpContext.Session.SetInt32("UUID", newUser.UserId);
            return RedirectToAction("Success");
        }
        else
        {
            return View("Index");
        }
    }
    [Session]
    [HttpGet("Success")]
    public IActionResult Success()
    {
        return View();
    }


    [HttpPost("users/login")]
    public IActionResult Login(Login newLog)

    {
        if (ModelState.IsValid)
        {
            // If initial ModelState is valid, query for a user with the provided email        
            User? userInDb = _context.Users.FirstOrDefault(u => u.Email == newLog.LoginEmail);
            // If no user exists with the provided email        
            if (userInDb == null)
            {
                // Add an error to ModelState and return to View!            
                ModelState.AddModelError("LoginPassword", "Invalid Credentials");
                return View("Index");
            }
            // Otherwise, we have a user, now we need to check their password                 
            // Initialize hasher object        
            PasswordHasher<Login> hasher = new PasswordHasher<Login>();
            // Verify provided password against hash stored in db        
            var result = hasher.VerifyHashedPassword(newLog, userInDb.Password, newLog.LoginPassword);                                    // Result can be compared to 0 for failure        
            if (result == 0)
            {
                // Handle failure (this should be similar to how "existing email" is handled)   
                ModelState.AddModelError("LoginPassword", "Invalid Credentials");
                return View("Index");
            }
            // Handle success (this should route to an internal page)  

            HttpContext.Session.SetInt32("UUID", userInDb.UserId);
            return RedirectToAction("Success");
        }
        else
        {
            return View("Index");
        }
    }


    [HttpPost("users/logout")]
    public IActionResult Logout()
    {
        // HttpContext.Session.Clear();
        HttpContext.Session.Remove("UUID");
        return RedirectToAction("Index");
    }


    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public IActionResult Error()
    {
        return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
    }
}