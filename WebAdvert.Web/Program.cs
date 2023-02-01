var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddCognitoIdentity();
builder.Services.AddControllersWithViews();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment()) app.UseExceptionHandler("/Home/Error");
app.UseStaticFiles();

app.UseRouting();

app.UseAuthorization();

app.UseAuthentication();
app.MapControllerRoute(
	"default",
	"{controller=Home}/{action=Index}/{id?}");

app.Run();