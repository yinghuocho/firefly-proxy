$('form').find('.alert').each(function(){
    $(this).css('display', 'none');
});
 
$('form').submit(function() {
    var data = $(this).serialize();
    var frm  = this;
    var url  = frm.action;
    

    $.ajax({
        url: url,
        type: 'POST',
        data: data,
        dataType:'JSON',
        success: function(data) {
            if (data.message) {
                msgbox = $(frm).find('span.alert-success');
                if (msgbox) {
                    msgbox.html(data.message);
                    msgbox.css('display', 'inline');
                    msgbox.fadeOut(2000, function(){
                        msgbox.html('');
                        location.reload();
                    });
                }
            }
        },
        error: function(jqXHR, textStatus, errorThrown) {
            if (jqXHR.responseJSON[0].message) {
                msgbox = $(frm).find('span.alert-danger');
                if (msgbox) {
                    msgbox.html(jqXHR.responseJSON[0].message);
                    msgbox.css('display', 'inline');
                    msgbox.fadeOut(2000, function(){
                        msgbox.html('');
                        location.reload();
                    });
                }
            }
        }
    })
    return false;  
});