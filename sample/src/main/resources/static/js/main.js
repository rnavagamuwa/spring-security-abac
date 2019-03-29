var headers = [];

$(document).ready(function () {

    $("#addHeaderButton").click(function () {
        headers[$("#headerKey").val()] = $("#headerValue").val();
        $("#headersList").append("<li>Header Key : " + $("#headerKey").val() + " | Header Value : " + $("#headerValue").val() + "</li>");
        $("#headerKey").val("");
        $("#headerValue").val("");
    });

    $("#submitRequestButton").click(function (event) {

        fire_ajax_submit();

    });
});

function fire_ajax_submit() {

    $("#btn-search").prop("disabled", true);

    $.ajax({
        type: "POST",
        contentType: "application/json",
        url: "/auth",
        data: JSON.stringify(""),
        dataType: 'json',
        cache: false,
        timeout: 600000,
        headers: headers,
        success: function (data) {

            var json = "<pre>"
                + JSON.stringify(data, null, 4) + "</pre>";
            $('#feedback').html(json);

            console.log("SUCCESS : ", data);
            $("#btn-search").prop("disabled", false);

            $("#headersList").empty();
            headers = [];

        },
        error: function (e) {

            var json = "<pre>"
                + e.responseText + "</pre>";
            $('#feedback').html(json);

            console.log("ERROR : ", e);
            $("#btn-search").prop("disabled", false);

        }
    });

}